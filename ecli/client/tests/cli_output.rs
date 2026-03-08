use std::process::Command;

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ecli-rs"))
        .args(args)
        .output()
        .expect("failed to run ecli binary")
}

#[cfg(feature = "native")]
#[test]
fn help_output_uses_public_binary_name() {
    let output = run_cli(&["-h"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ecli subcommands, including run, push, pull"));
    assert!(stdout.contains("Usage: ecli [COMMAND]"));
    assert!(!stdout.contains("ecli-rs"));
}

#[cfg(not(feature = "native"))]
#[test]
fn help_output_uses_public_binary_name_without_run() {
    let output = run_cli(&["-h"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ecli subcommands, including push, pull"));
    assert!(stdout.contains("Usage: ecli [COMMAND]"));
    assert!(!stdout.contains("\n  run "));
    assert!(!stdout.contains("ecli-rs"));
}

#[cfg(feature = "native")]
#[test]
fn legacy_positional_invocation_shows_public_migration_hint() {
    for arg in ["./prog.json", "prog", "alpine"] {
        let output = run_cli(&[arg]);
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("use `ecli run <program>` instead"));
        assert!(stderr.contains("Usage: ecli [COMMAND]"));
        assert!(!stderr.contains("ecli-rs"));
    }
}

#[cfg(feature = "native")]
#[test]
fn subcommand_typos_keep_clap_unknown_subcommand_error() {
    for arg in ["pus", "pll", "runn", "psuh"] {
        let output = run_cli(&[arg]);
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("unrecognized subcommand '{arg}'")));
        assert!(!stderr.contains("use `ecli run <program>` instead"));
        assert!(stderr.contains("Usage: ecli [COMMAND]"));
        assert!(!stderr.contains("ecli-rs"));
    }
}

#[cfg(not(feature = "native"))]
#[test]
fn no_native_error_output_keeps_public_binary_name() {
    let output = run_cli(&["./prog.json"]);
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unrecognized subcommand './prog.json'"));
    assert!(stderr.contains("Usage: ecli [COMMAND]"));
    assert!(!stderr.contains("ecli-rs"));
}
