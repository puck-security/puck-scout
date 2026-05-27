use serde::{Deserialize, Deserializer, Serialize};

/// Deserialise an array-shaped field, tolerating `null` (Go's encoding/json
/// emits `null` for nil slices).  Maps `null` and missing → empty Vec.
fn null_to_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(d).map(Option::unwrap_or_default)
}

/// A command request received from the MCP server during polling.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandRequest {
    pub command_id: String,
    pub investigation_id: String,
    pub command: String,
    #[serde(default, deserialize_with = "null_to_empty")]
    pub args: Vec<String>,
    pub timeout_seconds: u64,
}

/// The result of executing a single command.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandResult {
    pub command_id: String,
    pub command: String,
    #[serde(default, deserialize_with = "null_to_empty")]
    pub args: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response from the MCP server when the agent polls for work.
/// 200 with commands, or 204 No Content (handled at HTTP level).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PollResponse {
    pub commands: Vec<CommandRequest>,
}

/// Payload the agent sends when submitting results.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResultSubmission {
    pub agent_id: String,
    pub hostname: String,
    pub investigation_id: String,
    pub results: Vec<CommandResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Go's encoding/json marshals a nil []string as JSON `null`, not as
    // `[]`.  The mcp server now initialises slices to empty (server-side
    // fix shipped earlier), but the agent's `null_to_empty` deserialiser
    // is the belt-and-suspenders defence for any wire-format drift —
    // pre-fix puck-mcp servers in the wild, third-party MCP servers, etc.
    // These tests pin the behaviour so a future refactor can't quietly
    // drop the tolerance.

    #[test]
    fn args_null_deserialises_to_empty_vec() {
        let json = r#"{
            "command_id": "abc",
            "investigation_id": "inv-1",
            "command": "whoami",
            "args": null,
            "timeout_seconds": 30
        }"#;
        let req: CommandRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.args, Vec::<String>::new(), "null args -> empty Vec");
    }

    #[test]
    fn args_missing_deserialises_to_empty_vec() {
        // args entirely absent (some Go code paths omit empty slices)
        let json = r#"{
            "command_id": "abc",
            "investigation_id": "inv-1",
            "command": "whoami",
            "timeout_seconds": 30
        }"#;
        let req: CommandRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.args, Vec::<String>::new(), "missing args -> empty Vec");
    }

    #[test]
    fn args_empty_array_deserialises_to_empty_vec() {
        let json = r#"{
            "command_id": "abc",
            "investigation_id": "inv-1",
            "command": "whoami",
            "args": [],
            "timeout_seconds": 30
        }"#;
        let req: CommandRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.args, Vec::<String>::new(), "[] args -> empty Vec");
    }

    #[test]
    fn args_populated_array_deserialises_normally() {
        let json = r#"{
            "command_id": "abc",
            "investigation_id": "inv-1",
            "command": "ls",
            "args": ["-la", "/tmp"],
            "timeout_seconds": 30
        }"#;
        let req: CommandRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.args, vec!["-la", "/tmp"]);
    }

    #[test]
    fn command_result_args_null_also_tolerated() {
        // Same deserialiser applied to CommandResult.args — verify it works
        // there too (server might echo back null in a result it received).
        let json = r#"{
            "command_id": "abc",
            "command": "whoami",
            "args": null,
            "stdout": "root\n",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 12
        }"#;
        let res: CommandResult = serde_json::from_str(json).expect("parse");
        assert_eq!(res.args, Vec::<String>::new());
    }
}
