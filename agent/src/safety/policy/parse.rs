use super::errors::PolicyError;
use super::types::{BinaryPolicy, FlagSpec, SimpleValueKind, TaggedValueKind, ValueKind};

#[derive(Debug)]
pub struct ParsedArgs {
    pub subcommand: Option<Vec<String>>,
    pub positionals: Vec<String>,
    pub flags: Vec<(String, Option<String>)>,
}

impl ParsedArgs {
    /// Flatten back into a normalised argv: [subcommand…, flags…, positionals…].
    /// Order is deterministic and chosen by the validator, not the caller.
    pub fn into_normalised_argv(self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(sc) = self.subcommand {
            out.extend(sc);
        }
        for (name, val) in self.flags {
            out.push(name);
            if let Some(v) = val {
                out.push(v);
            }
        }
        out.extend(self.positionals);
        out
    }
}

pub fn parse_args(p: &BinaryPolicy, args: &[String]) -> Result<ParsedArgs, PolicyError> {
    let mut subcommand = None;
    let mut i = 0;

    if p.subcommand_required {
        let (consumed, sc) = consume_subcommand(p, args)?;
        subcommand = Some(sc);
        i = consumed;
    }

    let mut flags: Vec<(String, Option<String>)> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();

    while i < args.len() {
        let tok = &args[i];
        if tok.starts_with('-') {
            // Belt-and-suspenders forbidden-flag check.
            if p.forbidden_flags.iter().any(|f| f == tok) {
                return Err(PolicyError::ForbiddenFlag {
                    binary: p.name.clone(),
                    flag: tok.clone(),
                });
            }
            let spec = p.flags.iter().find(|f| &f.name == tok);
            match spec {
                Some(spec) => match needs_value(&spec.value) {
                    false => {
                        flags.push((tok.clone(), None));
                        i += 1;
                    }
                    true => {
                        let val = args
                            .get(i + 1)
                            .ok_or_else(|| PolicyError::MissingFlagValue {
                                binary: p.name.clone(),
                                flag: tok.clone(),
                            })?;
                        validate_value(p, spec, val)?;
                        flags.push((tok.clone(), Some(val.clone())));
                        i += 2;
                    }
                },
                None if is_combined_short_eligible(tok) && combined_short_admits(p, tok) => {
                    // Unix combined-short convention: `-XYZ` where each
                    // of X/Y/Z is a single-char flag with value=none.
                    // We accept the token as-is (keep normalised form
                    // identical to input — the binary parses combined
                    // shorts natively, no need to expand).  See
                    // combined_short_admits for the legitimacy check.
                    flags.push((tok.clone(), None));
                    i += 1;
                }
                None => {
                    return Err(PolicyError::UnknownFlag {
                        binary: p.name.clone(),
                        flag: tok.clone(),
                    });
                }
            }
        } else {
            // Positional handling
            let pos = p
                .positional
                .as_ref()
                .ok_or_else(|| PolicyError::UnexpectedPositional {
                    binary: p.name.clone(),
                    token: tok.clone(),
                })?;
            if positionals.len() >= pos.max {
                return Err(PolicyError::PositionalCountOutOfRange {
                    binary: p.name.clone(),
                    got: positionals.len() + 1,
                    min: pos.min,
                    max: pos.max,
                });
            }
            validate_positional(p, pos, tok)?;
            positionals.push(tok.clone());
            i += 1;
        }
    }

    if let Some(pos) = &p.positional {
        if positionals.len() < pos.min {
            return Err(PolicyError::PositionalCountOutOfRange {
                binary: p.name.clone(),
                got: positionals.len(),
                min: pos.min,
                max: pos.max,
            });
        }
    }

    Ok(ParsedArgs {
        subcommand,
        positionals,
        flags,
    })
}

fn needs_value(v: &ValueKind) -> bool {
    !matches!(v, ValueKind::Simple(SimpleValueKind::None))
}

/// is_combined_short_eligible: a token MIGHT be a combined-short of
/// value-less flags if it starts with single `-` (not `--`) and has
/// at least two chars after the dash.  `-l` is just a regular short;
/// `--list` is a long flag; `-la` is the form we want to split.
fn is_combined_short_eligible(tok: &str) -> bool {
    tok.starts_with('-') && !tok.starts_with("--") && tok.len() >= 3
}

/// combined_short_admits: returns true iff every char after the leading
/// `-` is a legitimate value-less flag in `p`.  Mirrors the standard
/// Unix convention that `ls -la` means `ls -l -a`.  Deliberately
/// rejects combinations that include a value-taking flag (`-n50` form);
/// the LLM should pass `-n 50` as two separate argv tokens for those.
fn combined_short_admits(p: &BinaryPolicy, tok: &str) -> bool {
    let rest = &tok[1..]; // strip leading '-'
    if rest.is_empty() {
        return false;
    }
    for c in rest.chars() {
        let single = format!("-{c}");
        match p.flags.iter().find(|f| f.name == single) {
            Some(spec) if !needs_value(&spec.value) => continue,
            _ => return false,
        }
    }
    true
}

fn validate_value(p: &BinaryPolicy, spec: &FlagSpec, val: &str) -> Result<(), PolicyError> {
    use SimpleValueKind::*;
    match &spec.value {
        ValueKind::Simple(None) => unreachable!("None is consumed above"),
        ValueKind::Simple(String) => validate_string(p, &spec.name, val),
        ValueKind::Simple(Glob) => validate_glob(p, &spec.name, val),
        ValueKind::Simple(Uint) => validate_uint(p, &spec.name, val),
        ValueKind::Simple(Duration) => validate_duration(p, &spec.name, val),
        ValueKind::Simple(FsPath) => validate_fs_path(p, &spec.name, val, &[]),
        ValueKind::Tagged(TaggedValueKind::Enum { values }) => {
            if values.iter().any(|v| v == val) {
                Ok(())
            } else {
                Err(PolicyError::BadFlagValue {
                    binary: p.name.clone(),
                    flag: spec.name.clone(),
                    reason: "value not in enum",
                })
            }
        }
        ValueKind::Tagged(TaggedValueKind::FsPath {
            restrict_to_prefixes,
        }) => validate_fs_path(p, &spec.name, val, restrict_to_prefixes),
    }
}

fn validate_string(p: &BinaryPolicy, flag: &str, val: &str) -> Result<(), PolicyError> {
    if val.len() > 4096 {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "string too long",
        });
    }
    if val
        .chars()
        .any(|c| c == '\0' || (c.is_control() && c != '\t'))
    {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "control byte in string",
        });
    }
    Ok(())
}

fn validate_glob(p: &BinaryPolicy, flag: &str, val: &str) -> Result<(), PolicyError> {
    validate_string(p, flag, val)?;
    if val.contains([';', '\\', '$', '`']) {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "glob contains shell-metacharacter byte",
        });
    }
    Ok(())
}

fn validate_uint(p: &BinaryPolicy, flag: &str, val: &str) -> Result<(), PolicyError> {
    if val.is_empty() || val.len() > 10 || !val.chars().all(|c| c.is_ascii_digit()) {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "not a uint",
        });
    }
    Ok(())
}

fn validate_duration(p: &BinaryPolicy, flag: &str, val: &str) -> Result<(), PolicyError> {
    let re_ok = {
        let mut chars = val.chars().peekable();
        if matches!(chars.peek(), Some('+') | Some('-')) {
            chars.next();
        }
        let mut digits = 0;
        while let Some(c) = chars.peek() {
            if c.is_ascii_digit() {
                chars.next();
                digits += 1;
            } else {
                break;
            }
        }
        let suffix_ok = matches!(
            chars.next(),
            None | Some('s' | 'm' | 'h' | 'd' | 'w' | 'M' | 'y')
        );
        digits > 0 && digits <= 10 && suffix_ok && chars.next().is_none()
    };
    if !re_ok {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "not a duration",
        });
    }
    Ok(())
}

fn validate_fs_path(
    p: &BinaryPolicy,
    flag: &str,
    val: &str,
    prefixes: &[String],
) -> Result<(), PolicyError> {
    if val.is_empty() || val.contains('\0') {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "empty or NUL in path",
        });
    }
    // Reject shell metacharacters in path values.  Same blocklist as
    // token_matches (see parse.rs::token_matches comment for the
    // rationale).  Without this, a positional like `C:/Users/foo; rm`
    // on PowerShell would admit through fs_path validation (the prefix
    // matches) and then PowerShell would parse the trailing `; rm` as
    // a second statement via -Command's script-concatenation rule.
    // Legitimate paths don't contain these chars — spaces are fine
    // (Windows "Program Files"); semicolons/pipes/backticks are not.
    if val
        .chars()
        .any(|c| matches!(c, ';' | '|' | '&' | '`' | '(' | ')' | '{' | '}'))
    {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "shell metacharacter in path",
        });
    }
    if !prefixes.is_empty() && !prefixes.iter().any(|pfx| val.starts_with(pfx.as_str())) {
        return Err(PolicyError::BadFlagValue {
            binary: p.name.clone(),
            flag: flag.into(),
            reason: "path not in restrict_to_prefixes",
        });
    }
    Ok(())
}

fn validate_positional(
    p: &BinaryPolicy,
    pos: &super::types::PositionalSpec,
    val: &str,
) -> Result<(), PolicyError> {
    use SimpleValueKind::*;
    match &pos.kind {
        ValueKind::Simple(String) => validate_string(p, "<positional>", val),
        ValueKind::Simple(Glob) => validate_glob(p, "<positional>", val),
        ValueKind::Simple(Uint) => validate_uint(p, "<positional>", val),
        ValueKind::Simple(Duration) => validate_duration(p, "<positional>", val),
        ValueKind::Simple(FsPath) => {
            validate_fs_path(p, "<positional>", val, &pos.restrict_to_prefixes)
        }
        ValueKind::Simple(None) => Err(PolicyError::BadPositional {
            binary: p.name.clone(),
            reason: "positional kind cannot be 'none'",
        }),
        ValueKind::Tagged(super::types::TaggedValueKind::Enum { values }) => {
            if values.iter().any(|v| v == val) {
                Ok(())
            } else {
                Err(PolicyError::BadPositional {
                    binary: p.name.clone(),
                    reason: "positional value not in enum",
                })
            }
        }
        ValueKind::Tagged(super::types::TaggedValueKind::FsPath {
            restrict_to_prefixes,
        }) => validate_fs_path(p, "<positional>", val, restrict_to_prefixes),
    }
}

fn consume_subcommand(
    p: &BinaryPolicy,
    args: &[String],
) -> Result<(usize, Vec<String>), PolicyError> {
    if !p.subcommand_required {
        return Ok((0, vec![]));
    }
    if args.is_empty() {
        return Err(PolicyError::SubcommandRequired {
            binary: p.name.clone(),
        });
    }

    // Pre-tokenise each subcommand entry; build a list sorted longest-first.
    let mut entries: Vec<Vec<&str>> = p
        .subcommands
        .iter()
        .map(|s| s.split_whitespace().collect::<Vec<_>>())
        .collect();
    entries.sort_by_key(|toks| std::cmp::Reverse(toks.len()));

    for entry in &entries {
        if entry.len() > args.len() {
            continue;
        }
        let matches_all = entry
            .iter()
            .zip(args.iter())
            .all(|(pattern, input)| token_matches(pattern, input));
        if matches_all {
            let consumed: Vec<String> = args[..entry.len()].to_vec();
            return Ok((entry.len(), consumed));
        }
    }

    Err(PolicyError::UnknownSubcommand {
        binary: p.name.clone(),
        subcommand: args[..args.len().min(2)].join(" "),
    })
}

fn token_matches(pattern: &str, input: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        if !input.starts_with(prefix) {
            return false;
        }
        // Glob matches in subcommand grammar are meant to match a single
        // argv token — an AWS verb (`list-users`), a PowerShell cmdlet
        // (`Get-Process`), a git subcommand (`ls-files`), a cmdkey
        // credential target (`TERMSRV/server.example.com`).  We block
        // characters that would let an attacker smuggle a multi-
        // statement payload past the prefix check inside a single
        // token, e.g. `-Command "Get-Process | Stop-Process"`:
        //
        //   - `;` statement separator (cmd.exe + PowerShell)
        //   - `|` pipeline (PowerShell + many shells)
        //   - `&` call operator (PowerShell), background (POSIX shells)
        //   - `(` `)` subexpression / call grouping
        //   - `{` `}` script block
        //   - `` ` `` PowerShell line-continuation / escape
        //   - whitespace inside a single token implies multi-token
        //     payload smuggled past tokenisation
        //
        // We deliberately allow `/`, `:`, `.`, `\`, `_`, `-`, alnum —
        // those appear in legitimate identifiers (cmdkey targets,
        // Windows paths, FQDNs, cmdlet names).
        return !input.chars().any(|c| {
            matches!(
                c,
                ';' | '|' | '&' | '(' | ')' | '{' | '}' | '`' | ' ' | '\t' | '\n' | '\r'
            )
        });
    }
    pattern == input
}

#[cfg(test)]
mod tests {
    use super::super::types::{BinaryPolicy, FlagSpec, PositionalSpec, SimpleValueKind, ValueKind};
    use super::*;

    fn fixture() -> BinaryPolicy {
        BinaryPolicy {
            name: "find".into(),
            canonical_paths: vec!["/usr/bin/find".into()],
            positional: None,
            flags: vec![
                FlagSpec {
                    name: "-name".into(),
                    value: ValueKind::Simple(SimpleValueKind::Glob),
                },
                FlagSpec {
                    name: "-print".into(),
                    value: ValueKind::Simple(SimpleValueKind::None),
                },
                FlagSpec {
                    name: "-maxdepth".into(),
                    value: ValueKind::Simple(SimpleValueKind::Uint),
                },
            ],
            forbidden_flags: vec!["-exec".into(), "-fprint".into()],
            subcommand_required: false,
            subcommands: vec![],
        }
    }

    #[test]
    fn accepts_known_flag_with_value() {
        let p = fixture();
        let args = vec!["-name".into(), "*.conf".into()];
        let out = parse_args(&p, &args).unwrap();
        assert_eq!(out.flags, vec![("-name".into(), Some("*.conf".into()))]);
    }

    #[test]
    fn rejects_unknown_flag() {
        let p = fixture();
        let args = vec!["-bogus".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::UnknownFlag { .. }
        ));
    }

    #[test]
    fn rejects_forbidden_flag_explicitly() {
        let p = fixture();
        let args = vec!["-fprint".into(), "/tmp/x".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::ForbiddenFlag { .. }
        ));
    }

    #[test]
    fn rejects_missing_flag_value() {
        let p = fixture();
        let args = vec!["-name".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::MissingFlagValue { .. }
        ));
    }

    #[test]
    fn rejects_glob_with_metacharacter() {
        let p = fixture();
        let args = vec!["-name".into(), "x$(id)".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::BadFlagValue { .. }
        ));
    }

    #[test]
    fn rejects_uint_with_non_digit() {
        let p = fixture();
        let args = vec!["-maxdepth".into(), "5abc".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::BadFlagValue { .. }
        ));
    }

    fn fixture_with_positional() -> BinaryPolicy {
        let mut p = fixture();
        p.positional = Some(PositionalSpec {
            kind: ValueKind::Simple(SimpleValueKind::FsPath),
            min: 1,
            max: 4,
            restrict_to_prefixes: vec!["/etc".into(), "/var".into()],
        });
        p
    }

    #[test]
    fn accepts_positional_within_count() {
        let p = fixture_with_positional();
        let args = vec!["/etc".into(), "-name".into(), "*.conf".into()];
        let out = parse_args(&p, &args).unwrap();
        assert_eq!(out.positionals, vec!["/etc".to_string()]);
        assert_eq!(out.flags, vec![("-name".into(), Some("*.conf".into()))]);
    }

    #[test]
    fn rejects_positional_when_disallowed() {
        let p = fixture(); // no positional spec
        let args = vec!["/etc".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::UnexpectedPositional { .. }
        ));
    }

    #[test]
    fn rejects_positional_outside_prefixes() {
        let p = fixture_with_positional();
        let args = vec!["/Users/dev".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::BadFlagValue { .. }
        ));
    }

    #[test]
    fn rejects_too_few_positionals() {
        let p = fixture_with_positional();
        let args: Vec<String> = vec![];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::PositionalCountOutOfRange { .. }
        ));
    }

    #[test]
    fn rejects_too_many_positionals() {
        let p = fixture_with_positional();
        let args = vec![
            "/etc/a".into(),
            "/etc/b".into(),
            "/var/x".into(),
            "/var/y".into(),
            "/var/z".into(),
        ];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::PositionalCountOutOfRange { .. }
        ));
    }

    fn fixture_aws() -> BinaryPolicy {
        BinaryPolicy {
            name: "aws".into(),
            canonical_paths: vec!["/usr/local/bin/aws".into()],
            positional: None,
            flags: vec![
                FlagSpec {
                    name: "--region".into(),
                    value: ValueKind::Simple(SimpleValueKind::String),
                },
                FlagSpec {
                    name: "--output".into(),
                    value: ValueKind::Tagged(super::super::types::TaggedValueKind::Enum {
                        values: vec!["json".into(), "text".into(), "table".into()],
                    }),
                },
            ],
            forbidden_flags: vec![],
            subcommand_required: true,
            subcommands: vec![
                "sts get-caller-identity".into(),
                "iam list-*".into(),
                "iam get-user".into(),
            ],
        }
    }

    #[test]
    fn accepts_exact_subcommand() {
        let p = fixture_aws();
        let args = vec!["sts".into(), "get-caller-identity".into()];
        let out = parse_args(&p, &args).unwrap();
        assert_eq!(
            out.subcommand,
            Some(vec!["sts".into(), "get-caller-identity".into()])
        );
    }

    #[test]
    fn accepts_wildcard_subcommand() {
        let p = fixture_aws();
        let args = vec![
            "iam".into(),
            "list-users".into(),
            "--output".into(),
            "json".into(),
        ];
        let out = parse_args(&p, &args).unwrap();
        assert_eq!(
            out.subcommand,
            Some(vec!["iam".into(), "list-users".into()])
        );
        assert_eq!(out.flags, vec![("--output".into(), Some("json".into()))]);
    }

    #[test]
    fn rejects_unknown_subcommand() {
        let p = fixture_aws();
        let args = vec!["iam".into(), "delete-user".into()];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::UnknownSubcommand { .. }
        ));
    }

    #[test]
    fn rejects_missing_subcommand() {
        let p = fixture_aws();
        let args: Vec<String> = vec![];
        assert!(matches!(
            parse_args(&p, &args).unwrap_err(),
            PolicyError::SubcommandRequired { .. }
        ));
    }
}
