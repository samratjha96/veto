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
    pub subcommand: String,
    pub flags: Vec<String>,
}

/// One tool's spec file in `specs/`.
#[derive(Deserialize)]
struct Tool {
    program: String,
    /// Options given before the subcommand that consume the next argument.
    #[serde(default)]
    global_value_options: Vec<String>,
    #[serde(default)]
    subcommands: HashMap<String, Subcommand>,
    /// Checked by the `spec_examples_hold` test; not used at run time.
    #[serde(default)]
    #[cfg_attr(not(test), allow(dead_code))]
    examples: Vec<Example>,
}

#[derive(Deserialize, Default)]
struct Subcommand {
    /// Short options and their canonical flag name. Long options are their own name.
    #[serde(default)]
    short: HashMap<char, String>,
    /// Options that consume the next argument, so it is not mistaken for a positional.
    #[serde(default)]
    value_options: Vec<String>,
    /// A positional argument starting with the prefix implies the flag.
    #[serde(default)]
    prefix_flags: HashMap<String, String>,
}

#[derive(Deserialize)]
#[cfg_attr(not(test), allow(dead_code))]
struct Example {
    command: String,
    subcommand: String,
    flags: Vec<String>,
}

static SPEC_FILES: Dir = include_dir!("$CARGO_MANIFEST_DIR/specs");

static TOOLS: LazyLock<HashMap<String, Tool>> = LazyLock::new(|| {
    SPEC_FILES
        .files()
        .filter(|f| f.path().extension().is_some_and(|e| e == "toml"))
        .map(|f| {
            let text = f.contents_utf8().expect("spec is UTF-8");
            let tool: Tool = toml::from_str(text)
                .unwrap_or_else(|e| panic!("invalid spec {}: {e}", f.path().display()));
            (tool.program.clone(), tool)
        })
        .collect()
});

pub fn describe(argv: &[String]) -> Facts {
    let Some(tool) = argv.first().and_then(|program| TOOLS.get(program)) else {
        return Facts::default();
    };

    let mut args = argv[1..].iter();
    let mut subcommand = None;
    while let Some(arg) = args.next() {
        if !arg.starts_with('-') {
            subcommand = Some(arg);
            break;
        }
        if tool.global_value_options.contains(arg) {
            args.next();
        }
    }
    let Some(subcommand) = subcommand else {
        return Facts::default();
    };

    let spec = tool.subcommands.get(subcommand);
    let takes_value = |arg: &String| spec.is_some_and(|s| s.value_options.contains(arg));
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
        } else if let Some(long) = arg.strip_prefix("--") {
            let (name, has_value) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            flags.push(name.to_string());
            if !has_value && takes_value(arg) {
                args.next();
            }
        } else {
            for c in arg[1..].chars() {
                let name = spec
                    .and_then(|s| s.short.get(&c))
                    .map_or_else(|| c.to_string(), Clone::clone);
                flags.push(name);
            }
            if takes_value(arg) {
                args.next();
            }
        }
    }
    flags.sort();
    flags.dedup();

    Facts {
        subcommand: subcommand.clone(),
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
        for tool in TOOLS.values() {
            for example in &tool.examples {
                let facts = describe(&example.command);
                assert_eq!(facts.subcommand, example.subcommand, "{}", example.command);
                assert_eq!(facts.flags, example.flags, "{}", example.command);
                checked += 1;
            }
        }
        assert!(checked > 0, "no spec examples found");
    }

    #[test]
    fn unknown_tools_have_no_facts() {
        assert_eq!(describe("ls -la"), Facts::default());
        assert_eq!(describe("git"), Facts::default());
    }
}
