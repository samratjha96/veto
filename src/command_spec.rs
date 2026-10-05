//! Declarative descriptions of how tools read their arguments.
//!
//! A policy should say `git push --force`, not list every spelling of it.
//! A spec records what a tool's options mean (`-f` is `--force`, a leading `+`
//! on a refspec forces), and `describe` turns an argv into the subcommand and
//! canonical flags that policies match on. A tool with no spec yields no facts.

use crate::effects::{Effect, EffectKind};
use include_dir::{Dir, include_dir};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Facts about one invocation, independent of how its arguments were spelled.
#[derive(Debug, Default, PartialEq)]
pub struct Facts {
    /// The spec's name for the tool, so `pip3` and `pip` match the same policies.
    /// Empty when the tool has no spec.
    pub program: String,
    pub subcommand: String,
    pub flags: Vec<String>,
    /// Indexes into argv of arguments that are plain data to the tool (option
    /// values, or everything for a tool whose arguments are text), not code or paths.
    pub data: Vec<usize>,
    /// Files the command writes or deletes, as the spec says it treats its operands.
    pub effects: Vec<Effect>,
}

/// One tool's spec file in `specs/`.
#[derive(Deserialize, Clone)]
struct Tool {
    program: String,
    /// Other names the same tool is invoked by, e.g. `pip3` for `pip`.
    #[serde(default)]
    aliases: Vec<String>,
    /// Options given before the subcommand that consume the next argument.
    #[serde(default)]
    global_value_options: Vec<String>,
    /// Arguments before the subcommand with these prefixes are not the subcommand
    /// (`cargo +nightly run`).
    #[serde(default)]
    skipped_prefixes: Vec<String>,
    /// Every argument is text for the tool to print or match, never a command or
    /// path (`echo`, `grep`).
    #[serde(default)]
    arguments_are_data: bool,
    /// Multi-character options use a single dash (`find -delete`, `terraform
    /// -auto-approve`), so `-abc` is the option `abc`, not the cluster `-a -b -c`.
    #[serde(default)]
    single_dash_long: bool,
    /// Empty for tools without subcommands, whose options sit at the top level.
    #[serde(default)]
    subcommands: HashMap<String, Subcommand>,
    #[serde(flatten)]
    options: Subcommand,
    /// Checked by the `spec_examples_hold` test; not used at run time.
    #[serde(default)]
    #[cfg_attr(not(test), allow(dead_code))]
    examples: Vec<Example>,
}

#[derive(Deserialize, Default, Clone)]
struct Subcommand {
    /// Subcommands below this one (`docker system prune`). An operand naming one
    /// switches to its spec and extends the reported subcommand (`system prune`).
    #[serde(default)]
    subcommands: HashMap<String, Subcommand>,
    /// Other spellings of the subcommand, e.g. `i` for `npm install`.
    #[serde(default)]
    aliases: Vec<String>,
    /// Short options and their canonical flag name. Long options are their own name.
    #[serde(default)]
    short: HashMap<char, String>,
    /// Options that consume a value, spelled as they appear (`-o`, `--output`), so the
    /// value is not mistaken for a positional. A short option takes the rest of its
    /// cluster as the value (`-ofile`) before taking the next argument.
    #[serde(default)]
    value_options: Vec<String>,
    /// Value options whose value is code the tool runs (`git -c core.pager=...`),
    /// so it stays visible to the signature scan instead of counting as data.
    #[serde(default)]
    code_options: Vec<String>,
    /// A positional argument starting with the prefix implies the flag.
    #[serde(default)]
    prefix_flags: HashMap<String, String>,
    /// What happens to every operand (`rm` deletes, `tee` writes).
    #[serde(default)]
    operands: Option<EffectKind>,
    /// With two or more operands: what happens to all but the last (`mv` deletes).
    #[serde(default)]
    sources: Option<EffectKind>,
    /// With two or more operands: what happens to the last (`cp`, `mv` write).
    #[serde(default)]
    destination: Option<EffectKind>,
    /// An operand starting with the prefix acts on the rest of it (`dd of=PATH`).
    #[serde(default)]
    prefix_effects: HashMap<String, EffectKind>,
    /// Operand effects only apply with this flag (`sed -i`).
    #[serde(default)]
    effects_require_flag: Option<String>,
    /// The first operand is a script, not a file, unless `-e` or `-f` supplied it.
    #[serde(default)]
    script_operand: bool,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct Example {
    command: String,
    subcommand: String,
    flags: Vec<String>,
}

static SPEC_FILES: Dir = include_dir!("$CARGO_MANIFEST_DIR/specs");

static TOOLS: LazyLock<HashMap<String, Tool>> = LazyLock::new(|| {
    let mut tools = HashMap::new();
    for file in SPEC_FILES
        .files()
        .filter(|f| f.path().extension().is_some_and(|e| e == "toml"))
    {
        let text = file.contents_utf8().expect("spec is UTF-8");
        let tool: Tool = toml::from_str(text)
            .unwrap_or_else(|e| panic!("invalid spec {}: {e}", file.path().display()));
        for alias in &tool.aliases {
            tools.insert(alias.clone(), tool.clone());
        }
        tools.insert(tool.program.clone(), tool);
    }
    tools
});

pub fn describe(argv: &[String]) -> Facts {
    let Some(tool) = argv.first().and_then(|program| TOOLS.get(program)) else {
        return Facts::default();
    };

    let mut data = Vec::new();
    let mut args = argv.iter().enumerate().skip(1);
    let (mut subcommand, mut spec) = if tool.subcommands.is_empty() {
        (String::new(), Some(&tool.options))
    } else {
        let mut word = None;
        while let Some((_, arg)) = args.next() {
            if tool
                .skipped_prefixes
                .iter()
                .any(|p| arg.starts_with(p.as_str()))
            {
                continue;
            }
            if !arg.starts_with('-') {
                word = Some(arg);
                break;
            }
            if tool.global_value_options.contains(arg) {
                consume_value(&mut args, Some(&tool.options), arg, &mut data);
            }
        }
        let Some(word) = word else {
            return Facts::default();
        };
        match find_subcommand(&tool.subcommands, word) {
            Some((name, spec)) => (name.clone(), Some(spec)),
            None => (word.clone(), None),
        }
    };

    let takes_value = |spec: Option<&Subcommand>, option: &str| {
        spec.is_some_and(|s| s.value_options.iter().any(|o| o == option))
    };
    let mut flags = Vec::new();
    let mut operands: Vec<&str> = Vec::new();
    let mut options_ended = false;
    while let Some((_, arg)) = args.next() {
        if options_ended || !arg.starts_with('-') || arg == "-" {
            if !options_ended
                && operands.is_empty()
                && let Some((name, nested)) =
                    spec.and_then(|s| find_subcommand(&s.subcommands, arg))
            {
                subcommand = format!("{subcommand} {name}");
                spec = Some(nested);
                continue;
            }
            operands.push(arg);
            for (prefix, flag) in spec.iter().flat_map(|s| &s.prefix_flags) {
                if arg.starts_with(prefix.as_str()) {
                    flags.push(flag.clone());
                }
            }
        } else if arg == "--" {
            options_ended = true;
        } else if arg.starts_with("--") || (tool.single_dash_long && arg.len() > 2) {
            let long = arg.trim_start_matches('-');
            let (name, has_value) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            flags.push(name.to_string());
            if !has_value && takes_value(spec, arg) {
                consume_value(&mut args, spec, arg, &mut data);
            }
        } else {
            let cluster = &arg[1..];
            for (i, c) in cluster.char_indices() {
                let name = spec
                    .and_then(|s| s.short.get(&c))
                    .map_or_else(|| c.to_string(), Clone::clone);
                flags.push(name);
                if takes_value(spec, &format!("-{c}")) {
                    if i + c.len_utf8() == cluster.len() {
                        consume_value(&mut args, spec, &format!("-{c}"), &mut data);
                    }
                    break;
                }
            }
        }
    }
    flags.sort();
    flags.dedup();

    if tool.arguments_are_data {
        data = (1..argv.len()).collect();
    }
    let effects = spec.map_or_else(Vec::new, |s| file_effects(s, &operands, &flags));
    Facts {
        program: tool.program.clone(),
        subcommand,
        flags,
        data,
        effects,
    }
}

/// Takes the next argument as the value of `option`, recording it as data
/// unless the spec says it is code.
fn consume_value<'a>(
    args: &mut impl Iterator<Item = (usize, &'a String)>,
    spec: Option<&Subcommand>,
    option: &str,
    data: &mut Vec<usize>,
) {
    let is_code = spec.is_some_and(|s| s.code_options.iter().any(|o| o == option));
    if let Some((i, _)) = args.next()
        && !is_code
    {
        data.push(i);
    }
}

fn find_subcommand<'a>(
    subcommands: &'a HashMap<String, Subcommand>,
    word: &str,
) -> Option<(&'a String, &'a Subcommand)> {
    subcommands
        .iter()
        .find(|(name, s)| *name == word || s.aliases.iter().any(|a| a == word))
}

fn file_effects(spec: &Subcommand, operands: &[&str], flags: &[String]) -> Vec<Effect> {
    if spec
        .effects_require_flag
        .as_ref()
        .is_some_and(|required| !flags.contains(required))
    {
        return Vec::new();
    }
    let has_script_flag = flags.iter().any(|f| f == "expression" || f == "file");
    let skip = usize::from(spec.script_operand && !has_script_flag);
    let operands: Vec<&str> = operands
        .iter()
        .copied()
        .filter(|o| !o.is_empty())
        .skip(skip)
        .collect();

    let mut effects = Vec::new();
    let mut add = |kind: EffectKind, path: &str| {
        effects.push(Effect {
            kind,
            path: path.to_string(),
        })
    };
    for operand in &operands {
        if let Some(kind) = spec.operands {
            add(kind, operand);
        }
        for (prefix, kind) in &spec.prefix_effects {
            if let Some(path) = operand.strip_prefix(prefix.as_str()) {
                add(*kind, path);
            }
        }
    }
    if let [sources @ .., destination] = operands.as_slice()
        && !sources.is_empty()
    {
        if let Some(kind) = spec.sources {
            sources.iter().for_each(|s| add(kind, s));
        }
        if let Some(kind) = spec.destination {
            add(kind, destination);
        }
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::*;

    fn describe(command: &str) -> Facts {
        super::describe(&command.split(' ').map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn spec_examples_hold() {
        let mut checked = 0;
        let mut failures = Vec::new();
        for tool in TOOLS.values() {
            for example in &tool.examples {
                let facts = describe(&example.command);
                if (&facts.subcommand, &facts.flags) != (&example.subcommand, &example.flags) {
                    failures.push(format!(
                        "{}: got {:?} {:?}, expected {:?} {:?}",
                        example.command,
                        facts.subcommand,
                        facts.flags,
                        example.subcommand,
                        example.flags
                    ));
                }
                checked += 1;
            }
        }
        assert!(checked > 0, "no spec examples found");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    fn effects(command: &str) -> Vec<(EffectKind, String)> {
        describe(command)
            .effects
            .into_iter()
            .map(|e| (e.kind, e.path))
            .collect()
    }

    #[test]
    fn operand_effects() {
        use EffectKind::{Delete, Write};
        let p = |s: &str| s.to_string();
        assert_eq!(effects("rm -rf a b"), [(Delete, p("a")), (Delete, p("b"))]);
        assert_eq!(effects("cp a b"), [(Write, p("b"))]);
        assert_eq!(effects("cp a"), []);
        assert_eq!(effects("mv a b"), [(Delete, p("a")), (Write, p("b"))]);
        assert_eq!(effects("dd if=x of=/y"), [(Write, p("/y"))]);
        assert_eq!(effects("sed -i s/a/b/ f"), [(Write, p("f"))]);
        assert_eq!(effects("sed s/a/b/ f"), []);
    }

    #[test]
    fn unknown_tools_have_no_facts() {
        assert_eq!(describe("ls -la"), Facts::default());
        assert_eq!(describe("git"), Facts::default());
    }
}
