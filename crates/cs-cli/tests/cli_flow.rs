//! End-to-end CLI flow tests: init -> add -> sync -> doctor, all driven through
//! the library `run()`.
//!
//! These tests run only **without** the `keyring-store` feature, so the device
//! identity is stored in an isolated file under the temp config dir (the OS
//! keychain would prompt and isn't test-friendly), and only on Unix (the
//! shared-store test uses symlinks). Run with:
//!   `cargo test -p cs-cli --no-default-features`

#![cfg(all(not(feature = "keyring-store"), unix))]

use clap::Parser;
use cs_cli::Cli;
use tempfile::TempDir;

fn parse(args: &[&str]) -> Cli {
    let mut all = vec!["config-sync"];
    all.extend_from_slice(args);
    Cli::try_parse_from(all).expect("clap parse")
}

#[test]
fn init_then_doctor_reports_healthy() {
    let dir = TempDir::new().unwrap();
    let cfg_dir = dir.path().to_path_buf();

    let cli = parse(&[
        "--config-dir",
        cfg_dir.to_str().unwrap(),
        "init",
        "--host",
        "test-host",
    ]);
    cs_cli::run(&cli).expect("init");

    // Config + identity now exist.
    assert!(cfg_dir.join("config.toml").exists());

    let doc = parse(&["--config-dir", cfg_dir.to_str().unwrap(), "doctor"]);
    cs_cli::run(&doc).expect("doctor healthy");
}

#[test]
fn init_is_idempotent_failure() {
    let dir = TempDir::new().unwrap();
    let cfg_dir = dir.path().to_path_buf();
    let cli = parse(&["--config-dir", cfg_dir.to_str().unwrap(), "init"]);
    cs_cli::run(&cli).expect("first init");
    let second = cs_cli::run(&cli);
    assert!(
        second.is_err(),
        "re-init must fail since config already exists"
    );
}

#[test]
fn add_then_list_shows_the_config() {
    let dir = TempDir::new().unwrap();
    let cfg_dir = dir.path().to_path_buf();
    cs_cli::run(&parse(&["--config-dir", cfg_dir.to_str().unwrap(), "init"])).unwrap();
    cs_cli::run(&parse(&[
        "--config-dir",
        cfg_dir.to_str().unwrap(),
        "add",
        "vim",
        "~/.vimrc",
        "--policy",
        "latest-wins",
    ]))
    .unwrap();
    let cfg = cs_config::Config::from_path(&cfg_dir.join("config.toml")).unwrap();
    assert_eq!(cfg.configs.len(), 1);
    assert_eq!(cfg.configs[0].name, "vim");
    assert_eq!(
        cfg.configs[0].conflict_policy,
        cs_config::ConflictPolicy::LatestWins
    );

    // `list` runs without error.
    cs_cli::run(&parse(&["--config-dir", cfg_dir.to_str().unwrap(), "list"])).unwrap();
}

#[test]
fn sync_round_trips_a_managed_file_through_local_store() {
    // Two separate config-sync installs sharing ONE store dir → a real two-
    // "device" sync through the CLI surface.
    let root = TempDir::new().unwrap();
    let device_a = root.path().join("deviceA");
    let device_b = root.path().join("deviceB");
    let shared_store = root.path().join("store");
    std::fs::create_dir_all(&device_a).unwrap();
    std::fs::create_dir_all(&device_b).unwrap();
    std::fs::create_dir_all(&shared_store).unwrap();

    // Device A: init, then point its store dir at the shared store.
    cs_cli::run(&parse(&[
        "--config-dir",
        device_a.to_str().unwrap(),
        "init",
        "--host",
        "A",
    ]))
    .unwrap();
    // Move device A's store dir to the shared location by recreating it as a symlink/dir.
    let _ = std::fs::remove_dir_all(device_a.join("store"));
    std::os::unix::fs::symlink(&shared_store, device_a.join("store")).unwrap();

    // Create the managed file under device A's home and add it.
    let home_a = root.path().join("homeA");
    std::fs::create_dir_all(&home_a).unwrap();
    std::fs::write(home_a.join(".vimrc"), b"set nu\n").unwrap();
    // Set HOME so PathResolver expands ~ for device A.
    std::env::set_var("HOME", &home_a);
    cs_cli::run(&parse(&[
        "--config-dir",
        device_a.to_str().unwrap(),
        "add",
        "vim",
        "~/.vimrc",
        "--policy",
        "latest-wins",
    ]))
    .unwrap();
    cs_cli::run(&parse(&[
        "--config-dir",
        device_a.to_str().unwrap(),
        "sync",
        "--non-interactive",
    ]))
    .unwrap();

    // Device B: init and share the same store.
    cs_cli::run(&parse(&[
        "--config-dir",
        device_b.to_str().unwrap(),
        "init",
        "--host",
        "B",
    ]))
    .unwrap();
    let _ = std::fs::remove_dir_all(device_b.join("store"));
    std::os::unix::fs::symlink(&shared_store, device_b.join("store")).unwrap();
    // Share device A's identity with device B (in real life this is the
    // add-device enrollment ceremony; here we test the CLI plumbing, so both
    // installs use the same identity to decrypt each other's blobs).
    std::fs::copy(device_a.join("identity.bin"), device_b.join("identity.bin")).unwrap();
    // Device B must also manage the same logical path so the pull writes it.
    let home_b = root.path().join("homeB");
    std::fs::create_dir_all(&home_b).unwrap();
    std::env::set_var("HOME", &home_b);
    cs_cli::run(&parse(&[
        "--config-dir",
        device_b.to_str().unwrap(),
        "add",
        "vim",
        "~/.vimrc",
        "--policy",
        "latest-wins",
    ]))
    .unwrap();
    cs_cli::run(&parse(&[
        "--config-dir",
        device_b.to_str().unwrap(),
        "sync",
        "--non-interactive",
    ]))
    .unwrap();

    // Device B now has the file pulled from A.
    assert_eq!(std::fs::read(home_b.join(".vimrc")).unwrap(), b"set nu\n");
}
