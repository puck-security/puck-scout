#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    PathInCommandName,
    InvalidCommandName(String),
    NotInAllowlist(String),
    UnknownFlag {
        binary: String,
        flag: String,
    },
    ForbiddenFlag {
        binary: String,
        flag: String,
    },
    MissingFlagValue {
        binary: String,
        flag: String,
    },
    BadFlagValue {
        binary: String,
        flag: String,
        reason: &'static str,
    },
    UnexpectedPositional {
        binary: String,
        token: String,
    },
    BadPositional {
        binary: String,
        reason: &'static str,
    },
    PositionalCountOutOfRange {
        binary: String,
        got: usize,
        min: usize,
        max: usize,
    },
    SubcommandRequired {
        binary: String,
    },
    UnknownSubcommand {
        binary: String,
        subcommand: String,
    },
    NoExecutableForBinary {
        binary: String,
    },
    ResolverRejectedAllCandidates {
        binary: String,
        rejections: Vec<(std::path::PathBuf, String)>,
    },
    PolicyDisabledByOverride {
        binary: String,
    },
}

impl PolicyError {
    /// Stable reason code used in audit log JSON.  Must match Go side's strings.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::PathInCommandName => "path_in_command_name",
            Self::InvalidCommandName(_) => "invalid_command_name",
            Self::NotInAllowlist(_) => "not_in_allowlist",
            Self::UnknownFlag { .. } => "unknown_flag",
            Self::ForbiddenFlag { .. } => "forbidden_flag",
            Self::MissingFlagValue { .. } => "missing_flag_value",
            Self::BadFlagValue { .. } => "bad_flag_value",
            Self::UnexpectedPositional { .. } => "unexpected_positional",
            Self::BadPositional { .. } => "bad_positional",
            Self::PositionalCountOutOfRange { .. } => "positional_count_out_of_range",
            Self::SubcommandRequired { .. } => "subcommand_required",
            Self::UnknownSubcommand { .. } => "unknown_subcommand",
            Self::NoExecutableForBinary { .. } => "no_executable_for_binary",
            Self::ResolverRejectedAllCandidates { .. } => "resolver_rejected_all_candidates",
            Self::PolicyDisabledByOverride { .. } => "policy_disabled_by_override",
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {}
