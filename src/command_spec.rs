//! Declarative descriptions of how tools read their arguments.
//!
//! A policy should say `git push --force`, not list every spelling of it.
//! A spec records what a tool's options mean (`-f` is `--force`, a leading `+`
//! on a refspec forces), and `describe` turns an argv into the subcommand and
//! canonical flags that policies match on. A tool with no spec yields no facts.

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
    /// A positional argument starting with the prefix implies the flag.
    #[serde(default)]
    prefix_flags: HashMap<String, String>,
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

    let mut args = argv[1..].iter();
    let (subcommand, spec) = if tool.subcommands.is_empty() {
        (String::new(), Some(&tool.options))
    } else {
        let mut word = None;
        while let Some(arg) = args.next() {
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
                args.next();
            }
        }
        let Some(word) = word else {
            return Facts::default();
        };
        match tool
            .subcommands
            .iter()
            .find(|(name, s)| *name == word || s.aliases.contains(word))
        {
            Some((name, spec)) => (name.clone(), Some(spec)),
            None => (word.clone(), None),
        }
    };

    let takes_value =
        |option: &str| spec.is_some_and(|s| s.value_options.iter().any(|o| o == option));
    let mut flags = Vec::new();
    let mut options_ended = false;
    while let Some(arg) = args.next() {
        if options_ended || !arg.starts_with('-') || arg == "-" {
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
            if !has_value && takes_value(arg) {
                args.next();
            }
        } else {
            let cluster = &arg[1..];
            for (i, c) in cluster.char_indices() {
                let name = spec
                    .and_then(|s| s.short.get(&c))
                    .map_or_else(|| c.to_string(), Clone::clone);
                flags.push(name);
                if takes_value(&format!("-{c}")) {
                    if i + c.len_utf8() == cluster.len() {
                        args.next();
                    }
                    break;
                }
            }
        }
    }
    flags.sort();
    flags.dedup();

    Facts {
        program: tool.program.clone(),
        subcommand,
        flags,
    }
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

    #[test]
    fn unknown_tools_have_no_facts() {
        assert_eq!(describe("ls -la"), Facts::default());
        assert_eq!(describe("git"), Facts::default());
    }
}
