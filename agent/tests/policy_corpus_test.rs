use puck_agent::safety::policy;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Vector {
    name: String,
    cmd: String,
    args: Vec<String>,
    expect: String, // "accept" | "reject"
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    normalised: Option<Vec<String>>,
}

#[test]
fn corpus_parity() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/policy-corpus.json");
    let raw = fs::read_to_string(&path).expect("corpus file");
    let vectors: Vec<Vector> = serde_json::from_str(&raw).expect("corpus parse");

    let mut failures: Vec<String> = Vec::new();
    for v in vectors {
        let got = policy::validate_parse(&v.cmd, &v.args);
        match (v.expect.as_str(), got) {
            ("accept", Ok(c)) => {
                if let Some(expected) = &v.normalised {
                    if &c.args != expected {
                        failures.push(format!(
                            "{}: argv mismatch: got {:?} want {:?}",
                            v.name, c.args, expected
                        ));
                    }
                }
            }
            ("accept", Err(e)) => {
                failures.push(format!("{}: expected accept, got {:?}", v.name, e))
            }
            ("reject", Err(e)) => {
                if let Some(expected) = &v.reason {
                    if e.reason_code() != expected {
                        failures.push(format!(
                            "{}: reason mismatch: got {} want {}",
                            v.name,
                            e.reason_code(),
                            expected
                        ));
                    }
                }
            }
            ("reject", Ok(c)) => {
                failures.push(format!("{}: expected reject, got Ok({:?})", v.name, c))
            }
            _ => unreachable!(),
        }
    }

    if !failures.is_empty() {
        panic!("corpus failures:\n{}", failures.join("\n"));
    }
}
