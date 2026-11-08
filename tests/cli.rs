//! Exit codes and the error surface of the real binary (SPEC Sections 5.5,
//! 5.6 and 12). None of these cases log in or touch a device.

use std::path::PathBuf;
use std::process::{Command, Output};

fn config_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sideload-cli-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn run(name: &str, args: &[&str]) -> Output {
    let dir = config_dir(name);
    let out = Command::new(env!("CARGO_BIN_EXE_sideload"))
        .args(args)
        .env("SIDELOADER_CONFIG_DIR", &dir)
        .env_remove("SIDELOADER_ANISETTE_SERVER")
        .env_remove("SIDELOADER_APPLE_ID")
        .env_remove("SIDELOADER_APPLE_PASSWORD")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn success_exits_zero() {
    let out = run("version", &["version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")));

    for args in [&["--help"][..], &["install", "--help"]] {
        let out = run("help", args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("Usage:"));
    }
}

#[test]
fn usage_errors_exit_one_with_code() {
    let out = run("unknown", &["no-such-command"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("error[invalid_arguments]"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn install_argument_errors_carry_the_phase() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["install", "/nonexistent/app.ipa"],
            "error[ipa_not_found] (ValidatingArguments)",
        ),
        (
            &["install", "a.ipa", "-o", "x.ipa", "--dry-run"],
            "error[invalid_arguments] (ValidatingArguments)",
        ),
        (
            &["install", "a.ipa", "--sidestore"],
            "error[invalid_arguments] (ValidatingArguments)",
        ),
        (
            &["install"],
            "error[invalid_arguments] (ValidatingArguments)",
        ),
    ];
    for (i, (args, expected)) in cases.iter().enumerate() {
        let out = run(&format!("install-{i}"), args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&out).contains(expected),
            "{args:?}: {}",
            stderr(&out)
        );
        // Nothing reaches the network or credential prompts.
        assert!(!stderr(&out).contains("Logging in"), "{args:?}");
    }
}

#[test]
fn diagnostics_do_not_carry_a_phase() {
    let out = run("bad-thread-count", &["--thread-count", "0", "team", "list"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("error[invalid_arguments]:"), "{err}");
}

#[test]
fn keep_temp_keeps_the_working_directory_on_failure() {
    // A file that passes argument validation but is not a zip fails in
    // PreparingBundle, after the working directory exists (SPEC 12, 16.5).
    let root = config_dir("keep-temp");
    let tmp = root.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let ipa = root.join("broken.ipa");
    std::fs::write(&ipa, b"not a zip").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sideload"))
        .arg("install")
        .arg(&ipa)
        .arg("-o")
        .arg(root.join("out.ipa"))
        .arg("--keep-temp")
        .env("SIDELOADER_CONFIG_DIR", root.join("config"))
        .env("TMPDIR", &tmp)
        .env("TMP", &tmp)
        .env("TEMP", &tmp)
        // No usbmuxd: Output mode continues without a device.
        .env("USBMUXD_SOCKET_ADDRESS", "127.0.0.1:9")
        .output()
        .unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("(PreparingBundle)"), "{err}");
    let kept = err
        .lines()
        .find_map(|l| l.strip_prefix("Working directory kept at "))
        .unwrap_or_else(|| panic!("no kept path in: {err}"));
    assert!(std::path::Path::new(kept).is_dir(), "{kept}");
    assert!(!err.contains("Logging in"), "failed before login");
    std::fs::remove_dir_all(&root).unwrap();
}
