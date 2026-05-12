use std::env;
use std::fs;
use std::io::{self, Read};

use agent_permission_normalizer::{normalize, raw_request_from_json};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input_path: Option<String> = None;
    let mut compact = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-i" | "--input" => input_path = args.next(),
            "--compact" => compact = true,
            "-h" | "--help" => {
                println!("agent-permission-normalizer\n\nUSAGE:\n  agent-permission-normalizer [--input <FILE>] [--compact]\n\nReads one RawRequest JSON document and emits a normalized permission request.");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let input = if let Some(path) = input_path {
        fs::read_to_string(path)?
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    };
    let raw = raw_request_from_json(&input)?;
    let normalized = normalize(raw)?;
    if compact {
        println!("{}", normalized.to_json_compact());
    } else {
        println!("{}", normalized.to_json_pretty());
    }
    Ok(())
}
