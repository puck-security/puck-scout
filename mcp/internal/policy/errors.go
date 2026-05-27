package policy

import "fmt"

type ErrorCode string

const (
	CodePathInCommandName         ErrorCode = "path_in_command_name"
	CodeInvalidCommandName        ErrorCode = "invalid_command_name"
	CodeNotInAllowlist            ErrorCode = "not_in_allowlist"
	CodeUnknownFlag               ErrorCode = "unknown_flag"
	CodeForbiddenFlag             ErrorCode = "forbidden_flag"
	CodeMissingFlagValue          ErrorCode = "missing_flag_value"
	CodeBadFlagValue              ErrorCode = "bad_flag_value"
	CodeUnexpectedPositional      ErrorCode = "unexpected_positional"
	CodeBadPositional             ErrorCode = "bad_positional"
	CodePositionalCountOutOfRange ErrorCode = "positional_count_out_of_range"
	CodeSubcommandRequired        ErrorCode = "subcommand_required"
	CodeUnknownSubcommand         ErrorCode = "unknown_subcommand"
	CodeNoExecutableForBinary     ErrorCode = "no_executable_for_binary"
	CodePolicyDisabledByOverride  ErrorCode = "policy_disabled_by_override"
)

type PolicyError struct {
	Code   ErrorCode
	Binary string
	Detail string
}

func (e *PolicyError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("policy: %s [%s]", e.Code, e.Binary)
	}
	return fmt.Sprintf("policy: %s [%s] %s", e.Code, e.Binary, e.Detail)
}
