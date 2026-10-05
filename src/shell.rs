//! Shell command normalization.
//!
//! Policies match on command text, but the shell rewrites that text before
//! running it: quotes collapse, `${IFS}` splits words, `bash -c` re-parses its
//! argument. This module resolves a command string the way the shell would and
//! returns each simple command as canonical text (`rm -rf /`), so policies
//! match what runs instead of how it was spelled.

use crate::command_spec;
use crate::effects::{Effect, EffectKind};
use brush_parser::ast::{
    AndOr, AndOrList, AssignmentName, AssignmentValue, Command, CommandPrefixOrSuffixItem,
    CompoundCommand, CompoundList, IoFileRedirectKind, IoFileRedirectTarget, IoRedirect, Pipeline,
    SimpleCommand, Word,
};
use brush_parser::word::{Parameter, ParameterExpr, WordPiece, WordPieceWithSource};
use brush_parser::{Parser, ParserOptions};
use std::collections::HashMap;
use std::io::Cursor;

/// Wrappers that run the command in their remaining arguments.
const PREFIX_WRAPPERS: &[&str] = &[
    "sudo", "env", "command", "exec", "nohup", "time", "nice", "builtin",
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];
const MAX_DEPTH: usize = 5;

/// One simple command as the shell would run it.
#[derive(Debug)]
pub struct Invocation {
    /// Canonical text, e.g. `rm -rf /`.
    pub text: String,
    pub program: String,
    /// Empty unless a command spec describes the program.
    pub subcommand: String,
    /// Canonical flag names from the command spec; empty without one.
    pub flags: Vec<String>,
    /// What signature rules should read: the command without arguments that are
    /// only data to it, so `echo "rm -rf /"` is not a destructive command.
    pub scan_text: String,
    /// Files the command writes or deletes, including redirect targets.
    pub effects: Vec<Effect>,
}

/// A redirection on a simple command.
struct Redirect {
    text: String,
    /// The file it truncates or appends to.
    writes: Option<String>,
}

impl Invocation {
    fn new(argv: &[String], redirects: &[Redirect]) -> Self {
        let mut argv = argv.to_vec();
        argv[0] = basename(&argv[0]).to_string();
        let facts = command_spec::describe(&argv);
        let mut text = argv.join(" ");
        let mut scan_text = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| !facts.data.contains(i))
            .map(|(_, a)| a.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let mut effects = facts.effects;
        for redirect in redirects {
            text.push(' ');
            text.push_str(&redirect.text);
            scan_text.push(' ');
            scan_text.push_str(&redirect.text);
            if let Some(path) = &redirect.writes {
                effects.push(Effect {
                    kind: EffectKind::Write,
                    path: path.clone(),
                });
            }
        }
        Self {
            text,
            scan_text,
            effects,
            program: if facts.program.is_empty() {
                argv[0].clone()
            } else {
                facts.program
            },
            subcommand: facts.subcommand,
            flags: facts.flags,
        }
    }

    /// Text that could not be parsed: policies see it as written.
    fn unparsed(text: &str) -> Self {
        Self {
            text: text.to_string(),
            scan_text: text.to_string(),
            effects: Vec::new(),
            program: String::new(),
            subcommand: String::new(),
            flags: Vec::new(),
        }
    }
}

/// What a command string runs, as the shell would see it.
#[derive(Debug, Default)]
pub struct Analysis {
    /// Every simple command, including those nested in `bash -c`, `eval`,
    /// command substitutions and wrappers like `sudo`.
    pub commands: Vec<Invocation>,
    /// Reasons the real command cannot be known before it runs.
    pub unresolved: Vec<String>,
}

pub fn analyze(command: &str) -> Analysis {
    let mut walker = Walker::default();
    if !walker.program(command, 0) {
        // Policies still see the raw text when it cannot be parsed.
        walker.analysis.commands.push(Invocation::unparsed(command));
    }
    walker.analysis
}

#[derive(Default)]
struct Walker {
    analysis: Analysis,
    /// Variables assigned a fully known value earlier in the same command.
    vars: HashMap<String, String>,
}

/// A word after quote removal and expansion.
struct Expanded {
    fields: Vec<String>,
    /// Part of the value is only known at run time.
    dynamic: bool,
}

impl Walker {
    /// Parses and walks `src`. Returns false when it does not parse.
    fn program(&mut self, src: &str, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            self.unresolved("commands nested too deeply to inspect");
            return true;
        }
        let mut parser = Parser::builder().build(Cursor::new(src));
        match parser.parse_program() {
            Ok(program) => {
                for list in &program.complete_commands {
                    self.list(list, depth);
                }
                true
            }
            Err(_) => {
                self.unresolved("command could not be parsed");
                false
            }
        }
    }

    fn unresolved(&mut self, reason: &str) {
        if !self.analysis.unresolved.iter().any(|r| r == reason) {
            self.analysis.unresolved.push(reason.to_string());
        }
    }

    fn list(&mut self, list: &CompoundList, depth: usize) {
        for item in &list.0 {
            self.and_or(&item.0, depth);
        }
    }

    fn and_or(&mut self, list: &AndOrList, depth: usize) {
        self.pipeline(&list.first, depth);
        for next in &list.additional {
            let (AndOr::And(p) | AndOr::Or(p)) = next;
            self.pipeline(p, depth);
        }
    }

    fn pipeline(&mut self, pipeline: &Pipeline, depth: usize) {
        for (i, command) in pipeline.seq.iter().enumerate() {
            let argv = self.command(command, depth);
            if i > 0 && reads_script_from_stdin(argv.as_deref()) {
                self.unresolved("a script is piped into a shell");
            }
        }
    }

    /// Returns the argv when `command` is a simple command.
    fn command(&mut self, command: &Command, depth: usize) -> Option<Vec<String>> {
        match command {
            Command::Simple(simple) => self.simple(simple, depth),
            Command::Compound(compound, _) => {
                self.compound(compound, depth);
                None
            }
            Command::Function(function) => {
                self.compound(&function.body.0, depth);
                None
            }
            Command::ExtendedTest(..) => None,
        }
    }

    fn compound(&mut self, compound: &CompoundCommand, depth: usize) {
        match compound {
            CompoundCommand::Arithmetic(_) => {}
            CompoundCommand::ArithmeticForClause(c) => self.list(&c.body.list, depth),
            CompoundCommand::BraceGroup(c) => self.list(&c.list, depth),
            CompoundCommand::Subshell(c) => self.list(&c.list, depth),
            CompoundCommand::ForClause(c) => self.list(&c.body.list, depth),
            CompoundCommand::CaseClause(c) => {
                for item in &c.cases {
                    if let Some(cmd) = &item.cmd {
                        self.list(cmd, depth);
                    }
                }
            }
            CompoundCommand::IfClause(c) => {
                self.list(&c.condition, depth);
                self.list(&c.then, depth);
                for clause in c.elses.iter().flatten() {
                    if let Some(condition) = &clause.condition {
                        self.list(condition, depth);
                    }
                    self.list(&clause.body, depth);
                }
            }
            CompoundCommand::WhileClause(c) | CompoundCommand::UntilClause(c) => {
                self.list(&c.0, depth);
                self.list(&c.1.list, depth);
            }
            CompoundCommand::Coprocess(c) => {
                self.command(&c.body, depth);
            }
        }
    }

    fn simple(&mut self, simple: &SimpleCommand, depth: usize) -> Option<Vec<String>> {
        let items = simple
            .prefix
            .iter()
            .flat_map(|p| &p.0)
            .chain(simple.suffix.iter().flat_map(|s| &s.0));

        let mut words: Vec<&Word> = simple.word_or_name.iter().collect();
        let mut redirects = Vec::new();
        let mut assignments = Vec::new();
        for item in items {
            match item {
                CommandPrefixOrSuffixItem::Word(w) => words.push(w),
                CommandPrefixOrSuffixItem::IoRedirect(r) => redirects.push(r),
                // `export X=1` carries the assignment as an ordinary argument.
                CommandPrefixOrSuffixItem::AssignmentWord(a, w) => {
                    if simple.word_or_name.is_some() {
                        words.push(w);
                    } else {
                        assignments.push(a);
                    }
                }
                CommandPrefixOrSuffixItem::ProcessSubstitution(_, sub) => {
                    self.list(&sub.list, depth + 1)
                }
            }
        }

        if simple.word_or_name.is_none() {
            self.record_assignments(&assignments, depth);
            return None;
        }

        let mut argv = Vec::new();
        for (i, word) in words.iter().enumerate() {
            let expanded = self.expand(&word.value, depth);
            if i == 0 && expanded.dynamic {
                self.unresolved("command name is built at run time");
            }
            argv.extend(expanded.fields);
        }
        if argv.is_empty() {
            return None;
        }
        argv[0] = basename(&argv[0]).to_string();

        let redirect_text: Vec<Redirect> = redirects
            .iter()
            .filter_map(|r| self.redirect(r, depth))
            .collect();
        self.analysis
            .commands
            .push(Invocation::new(&argv, &redirect_text));

        self.nested_commands(&argv, depth);
        Some(argv)
    }

    /// Follows commands that run another command: `sudo X`, `bash -c X`, `eval X`.
    fn nested_commands(&mut self, argv: &[String], depth: usize) {
        let mut rest = argv;
        while let Some(inner) = strip_wrapper(rest) {
            self.analysis.commands.push(Invocation::new(inner, &[]));
            rest = inner;
        }

        match rest.first().map(String::as_str) {
            Some("eval") => {
                let script = rest[1..].join(" ");
                self.program(&script, depth + 1);
            }
            Some(shell) if SHELLS.contains(&shell) => {
                let script_flag = rest
                    .iter()
                    .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'));
                if let Some(script) = script_flag.and_then(|i| rest.get(i + 1)) {
                    self.program(script, depth + 1);
                } else if script_flag.is_none() && rest[1..].iter().any(|a| !a.starts_with('-')) {
                    self.unresolved("a shell runs a script file");
                }
            }
            _ => {}
        }
    }

    /// Remembers `NAME=value` when the value is fully known, so a later `$NAME`
    /// resolves to it. A value only known at run time forgets the variable.
    fn record_assignments(&mut self, assignments: &[&brush_parser::ast::Assignment], depth: usize) {
        for assignment in assignments {
            let AssignmentName::VariableName(name) = &assignment.name else {
                continue;
            };
            let AssignmentValue::Scalar(word) = &assignment.value else {
                self.vars.remove(name);
                continue;
            };
            let expanded = self.expand(&word.value, depth);
            if expanded.dynamic || assignment.append {
                self.vars.remove(name);
            } else {
                self.vars.insert(name.clone(), expanded.fields.join(" "));
            }
        }
    }

    fn redirect(&mut self, redirect: &IoRedirect, depth: usize) -> Option<Redirect> {
        match redirect {
            IoRedirect::File(_, kind, IoFileRedirectTarget::Filename(word)) => {
                let op = match kind {
                    IoFileRedirectKind::Read => "<",
                    IoFileRedirectKind::Write | IoFileRedirectKind::Clobber => ">",
                    IoFileRedirectKind::Append => ">>",
                    IoFileRedirectKind::ReadAndWrite => "<>",
                    IoFileRedirectKind::DuplicateInput => "<&",
                    IoFileRedirectKind::DuplicateOutput => ">&",
                };
                let target = self.expand(&word.value, depth).fields.join(" ");
                let writes = matches!(
                    kind,
                    IoFileRedirectKind::Write
                        | IoFileRedirectKind::Clobber
                        | IoFileRedirectKind::Append
                        | IoFileRedirectKind::ReadAndWrite
                )
                .then(|| target.clone());
                Some(Redirect {
                    text: format!("{op} {target}"),
                    writes,
                })
            }
            IoRedirect::File(_, _, IoFileRedirectTarget::ProcessSubstitution(_, sub)) => {
                self.list(&sub.list, depth + 1);
                None
            }
            IoRedirect::HereString(_, word) => {
                let text = self.expand(&word.value, depth).fields.join(" ");
                Some(Redirect {
                    text: format!("<<< {text}"),
                    writes: None,
                })
            }
            _ => None,
        }
    }

    /// Applies quote removal, known variables and word splitting to one word.
    fn expand(&mut self, raw: &str, depth: usize) -> Expanded {
        let Ok(pieces) = brush_parser::word::parse(raw, &ParserOptions::default()) else {
            return Expanded {
                fields: vec![raw.to_string()],
                dynamic: true,
            };
        };
        let mut out = Expanded {
            fields: vec![String::new()],
            dynamic: false,
        };
        self.append_pieces(raw, &pieces, false, &mut out, depth);
        out.fields.retain(|f| !f.is_empty());
        out
    }

    fn append_pieces(
        &mut self,
        raw: &str,
        pieces: &[WordPieceWithSource],
        quoted: bool,
        out: &mut Expanded,
        depth: usize,
    ) {
        for p in pieces {
            let source = raw.get(p.start_index..p.end_index).unwrap_or("");
            match &p.piece {
                WordPiece::Text(t) | WordPiece::SingleQuotedText(t) => push(out, t),
                WordPiece::AnsiCQuotedText(t) => push(out, &decode_ansi_c(t)),
                WordPiece::EscapeSequence(e) => push(out, e.strip_prefix('\\').unwrap_or(e)),
                WordPiece::TildeExpansion(_) => push(out, source),
                WordPiece::DoubleQuotedSequence(inner)
                | WordPiece::GettextDoubleQuotedSequence(inner) => {
                    self.append_pieces(raw, inner, true, out, depth)
                }
                WordPiece::ParameterExpansion(expr) => {
                    self.append_parameter(expr, source, quoted, out)
                }
                WordPiece::CommandSubstitution(inner)
                | WordPiece::BackquotedCommandSubstitution(inner) => {
                    self.program(inner, depth + 1);
                    out.dynamic = true;
                    push(out, source);
                }
                WordPiece::ArithmeticExpression(_) => {
                    out.dynamic = true;
                    push(out, source);
                }
            }
        }
    }

    fn append_parameter(
        &mut self,
        expr: &ParameterExpr,
        source: &str,
        quoted: bool,
        out: &mut Expanded,
    ) {
        let ParameterExpr::Parameter {
            parameter: Parameter::Named(name),
            indirect: false,
        } = expr
        else {
            out.dynamic = true;
            return push(out, source);
        };

        // Unquoted, the default IFS splits the word where it appears.
        let value = if name == "IFS" && !quoted {
            Some(" ".to_string())
        } else {
            self.vars.get(name).cloned()
        };
        match value {
            Some(v) if quoted => push(out, &v),
            Some(v) => split_into_fields(out, &v),
            None => {
                out.dynamic = true;
                push(out, source);
            }
        }
    }
}

fn push(out: &mut Expanded, text: &str) {
    if let Some(last) = out.fields.last_mut() {
        last.push_str(text);
    }
}

/// Appends `text` as unquoted fields: whitespace ends the current field.
fn split_into_fields(out: &mut Expanded, text: &str) {
    for (i, part) in text.split(' ').enumerate() {
        if i > 0 {
            out.fields.push(String::new());
        }
        push(out, part);
    }
}

fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Options that consume the next argument, which would otherwise read as the command.
fn value_options(wrapper: &str) -> &'static [&'static str] {
    match wrapper {
        "sudo" => &["-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"],
        "env" => &["-u", "-C", "-S"],
        "nice" => &["-n"],
        _ => &[],
    }
}

/// For `sudo -u root rm -rf /` returns `rm -rf /`; None when `argv` is not a wrapper call.
fn strip_wrapper(argv: &[String]) -> Option<&[String]> {
    let wrapper = argv.first()?;
    if !PREFIX_WRAPPERS.contains(&wrapper.as_str()) {
        return None;
    }
    let value_options = value_options(wrapper);
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        if value_options.contains(&arg.as_str()) {
            i += 2;
        } else if arg.starts_with('-') || (wrapper == "env" && arg.contains('=')) {
            i += 1;
        } else {
            break;
        }
    }
    argv.get(i..).filter(|inner| !inner.is_empty())
}

/// A shell with no script argument executes whatever arrives on stdin.
fn reads_script_from_stdin(argv: Option<&[String]>) -> bool {
    let Some(argv) = argv else { return false };
    argv.first().is_some_and(|p| SHELLS.contains(&p.as_str()))
        && argv[1..].iter().all(|a| a.starts_with('-') && a != "-c")
}

/// Decodes the escapes in `$'...'`: `\xNN`, octal `\NNN`, and single-letter escapes.
fn decode_ansi_c(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('x') => {
                let hex: String = std::iter::from_fn(|| chars.next_if(|c| c.is_ascii_hexdigit()))
                    .take(2)
                    .collect();
                out.extend(u8::from_str_radix(&hex, 16).ok().map(char::from));
            }
            Some(d @ '0'..='7') => {
                let mut oct = d.to_string();
                oct.extend(
                    std::iter::from_fn(|| chars.next_if(|c| ('0'..='7').contains(c))).take(2),
                );
                out.extend(u8::from_str_radix(&oct, 8).ok().map(char::from));
            }
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(src: &str) -> Vec<String> {
        analyze(src).commands.into_iter().map(|c| c.text).collect()
    }

    #[test]
    fn quote_collapse() {
        assert_eq!(commands(r#"r""m -rf /"#), ["rm -rf /"]);
        assert_eq!(commands("r''m -rf /"), ["rm -rf /"]);
        assert_eq!(commands(r"\rm -rf /"), ["rm -rf /"]);
        assert_eq!(commands(r"r\m -rf /"), ["rm -rf /"]);
    }

    #[test]
    fn ifs_splits_words() {
        assert_eq!(commands("rm${IFS}-rf${IFS}/"), ["rm -rf /"]);
        assert_eq!(commands("rm$IFS-rf$IFS/"), ["rm -rf /"]);
    }

    #[test]
    fn ansi_c_quoting() {
        assert_eq!(commands(r"$'\x72\x6d' -rf /"), ["rm -rf /"]);
        assert_eq!(commands("$'rm' -rf /"), ["rm -rf /"]);
    }

    #[test]
    fn known_variables_resolve() {
        assert_eq!(commands("c=rm; $c -rf /"), ["rm -rf /"]);
        assert_eq!(commands("X=/; rm -rf $X"), ["rm -rf /"]);
        assert_eq!(commands("cmd='rm -rf /'; $cmd"), ["rm -rf /"]);
    }

    #[test]
    fn chains_pipes_and_compound_commands_split() {
        assert_eq!(
            commands("ls && git push --force origin main | cat"),
            ["ls", "git push --force origin main", "cat"]
        );
        assert_eq!(commands("if true; then rm -rf /; fi"), ["true", "rm -rf /"]);
    }

    #[test]
    fn path_and_wrappers_are_stripped() {
        let c = commands("sudo -u root /bin/rm -rf /");
        assert!(c.contains(&"rm -rf /".to_string()), "{c:?}");
        let c = commands("env FOO=1 command rm -rf /");
        assert!(c.contains(&"rm -rf /".to_string()), "{c:?}");
    }

    #[test]
    fn nested_scripts_are_walked() {
        assert!(commands("bash -c 'rm -rf /'").contains(&"rm -rf /".to_string()));
        assert!(commands("eval \"rm -rf /\"").contains(&"rm -rf /".to_string()));
        assert!(commands("echo $(rm -rf /)").contains(&"rm -rf /".to_string()));
    }

    #[test]
    fn redirect_targets_stay_in_the_command() {
        assert_eq!(
            commands("echo x >> ~/.ssh/authorized_keys"),
            ["echo x >> ~/.ssh/authorized_keys"]
        );
    }

    #[test]
    fn run_time_command_names_are_unresolved() {
        assert!(!analyze("$(echo rm) -rf /").unresolved.is_empty());
        assert!(!analyze("$unknown -rf /").unresolved.is_empty());
        assert!(!analyze("echo cm0= | base64 -d | sh").unresolved.is_empty());
        assert!(!analyze("rm -rf $(").unresolved.is_empty());
    }

    #[test]
    fn ordinary_commands_are_fully_resolved() {
        for src in [
            "ls -la",
            "echo $(git rev-parse HEAD)",
            "curl https://example.com | jq .",
            "cargo test --test x",
        ] {
            assert!(analyze(src).unresolved.is_empty(), "{src}");
        }
    }

    #[test]
    fn unparseable_text_is_kept_for_policies() {
        assert_eq!(commands("rm -rf $("), ["rm -rf $("]);
    }
}
