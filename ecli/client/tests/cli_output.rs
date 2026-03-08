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
    for arg in [
        "./prog.json",
        "prog",
        "alpine",
        "runner",
        "bun",
        "ru",
        "ur",
        "rn",
        "un",
        "rnu",
        "urn",
    ] {
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
fn plausible_run_like_names_still_show_public_migration_hint() {
    for arg in ["rune", "runa", "raun", "r1un", "rnun", "nrun", "urun"] {
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
    for arg in [
        "pus", "pll", "runn", "ruun", "runx", "run-", "psuh", "psu", "plu", "pushhhh", "runnnn",
        "nru", "unr", "nur", "nnrun",
    ] {
        let output = run_cli(&[arg]);
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("unrecognized subcommand '{arg}'")));
        assert!(!stderr.contains("use `ecli run <program>` instead"));
        assert!(stderr.contains("Usage: ecli [COMMAND]"));
        assert!(!stderr.contains("ecli-rs"));
    }
}

#[cfg(feature = "native")]
#[test]
fn unsuggested_run_typos_without_clap_tips_still_keep_unknown_subcommand_error() {
    for arg in ["nru", "unr", "nur", "nnrun"] {
        let output = run_cli(&[arg]);
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("unrecognized subcommand '{arg}'")));
        assert!(!stderr.contains("tip:"));
        assert!(!stderr.contains("use `ecli run <program>` instead"));
    }
}

#[cfg(feature = "native")]
#[test]
fn clap_suggestions_are_preserved_for_detected_subcommand_typos() {
    for (arg, suggestion) in [
        ("rrn", "run"),
        ("rrn-", "run"),
        ("rrn1", "run"),
        ("rnn-", "run"),
        ("rnn1", "run"),
        ("nnrun-", "run"),
        ("nnrun1", "run"),
        ("ruun", "run"),
        ("runx", "run"),
        ("run-", "run"),
        ("run1", "run"),
        ("run_", "run"),
        ("run.", "run"),
        ("r-un", "run"),
        ("ru-n", "run"),
        ("runn-", "run"),
        ("runn1", "run"),
        ("psu", "push"),
        ("plu", "pull"),
        ("pushhhh", "push"),
        ("runnnn", "run"),
    ] {
        let output = run_cli(&[arg]);
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("unrecognized subcommand '{arg}'")));
        assert!(stderr.contains("tip:"));
        assert!(stderr.contains(suggestion));
        assert!(!stderr.contains("use `ecli run <program>` instead"));
    }
}

#[cfg(feature = "native")]
#[test]
fn case_only_run_typos_keep_clap_unknown_subcommand_error() {
    for (arg, has_tip) in [("Run", true), ("RUN", false), ("rUn", true)] {
        let output = run_cli(&[arg]);
        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("unrecognized subcommand '{arg}'")));
        assert_eq!(stderr.contains("tip:"), has_tip);
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
