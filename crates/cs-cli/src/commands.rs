//! Subcommand implementations.

use crate::cli::{AddArgs, Command, InitArgs, RecoverArgs, SyncArgs};
use crate::state::{platform_to_str, AppState};
use crate::{build_store, Cli, CliError};
use cs_config::{ConfigSet, ConflictPolicy, Location};
use cs_keys::DeviceIdentity;
use cs_manifest::{DeviceId, Manifest};

/// Dispatch a parsed [`Cli`] to the right subcommand.
pub fn run(cli: &Cli) -> Result<(), CliError> {
    // The Tokio runtime drives the async sync command.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Plain(format!("runtime: {e}")))?;
    rt.block_on(run_async(cli))
}

async fn run_async(cli: &Cli) -> Result<(), CliError> {
    let state = AppState::new(cli.config_dir.clone(), !cli.no_biometrics)?;
    match &cli.command {
        Command::Init(args) => cmd_init(&state, args),
        Command::Add(args) => cmd_add(&state, args),
        Command::List => cmd_list(&state),
        Command::Sync(args) => cmd_sync(&state, args).await,
        Command::Recover(args) => cmd_recover(&state, args),
        Command::Doctor => cmd_doctor(&state),
    }
}

fn cmd_init(state: &AppState, args: &InitArgs) -> Result<(), CliError> {
    if state.config_exists() {
        return Err(CliError::Plain(format!(
            "config already exists at {}; remove it to re-init",
            state.config_path.display()
        )));
    }
    let host = args.host.clone().unwrap_or_else(hostname);
    let mut cfg = AppState::starter_config(&host);
    // Generate a device identity and persist it.
    let id = cs_keys::DeviceIdentity::new();
    let store = state.secret_store();
    state.store_identity(&store, &id).map_err(|e| {
        // A biometric store needs a signed+entitled build to create the ACL'd
        // item; give the user an actionable hint rather than a raw keychain err.
        match &e {
            CliError::Keys(cs_keys::KeysError::Keychain(msg)) if msg.contains("entitlement") => {
                CliError::Plain(format!(
                    "could not create a biometric-gated keychain item ({msg}).\n\
                     This usually means the binary isn't signed/entitled for Touch ID.\n\
                     Re-run with --no-biometrics to use the plain keychain/file store."
                ))
            }
            _ => e,
        }
    })?;
    state.save_config(&cfg)?;
    println!(
        "Initialized config-sync at {}.\nDevice id: {}\nIdentity stored in {}.\n\
         Add files with `config-sync add <name> <path>`, then `config-sync sync`.",
        state.config_dir.display(),
        cfg.identity.device_id,
        store_kind(&store)
    );
    // Mark cfg used so the unused-mut warning stays accurate.
    let _ = &mut cfg;
    Ok(())
}

fn cmd_add(state: &AppState, args: &AddArgs) -> Result<(), CliError> {
    let mut cfg = state.load_config()?;
    let policy = parse_policy(&args.policy)?;
    if cfg.configs.iter().any(|c| c.name == args.name) {
        return Err(CliError::Plain(format!(
            "a config named '{}' already exists",
            args.name
        )));
    }
    let platform = detect_platform();
    let host = hostname();
    cfg.configs.push(ConfigSet {
        name: args.name.clone(),
        conflict_policy: policy,
        ignore: Vec::new(),
        locations: vec![Location {
            host,
            platform: platform_to_str(platform).to_string(),
            path: args.path.clone(),
        }],
        fields: std::collections::BTreeMap::new(),
    });
    state.save_config(&cfg)?;
    println!("Added config '{}' -> {}", args.name, args.path);
    Ok(())
}

fn cmd_list(state: &AppState) -> Result<(), CliError> {
    let cfg = state.load_config()?;
    if cfg.configs.is_empty() {
        println!("(no configs yet; run `config-sync add <name> <path>`)");
        return Ok(());
    }
    for set in &cfg.configs {
        let loc = set
            .locations
            .first()
            .map(|l| l.path.as_str())
            .unwrap_or("?");
        println!(
            "{:<16} {:<10} {}",
            set.name,
            policy_str(set.conflict_policy),
            loc
        );
    }
    Ok(())
}

async fn cmd_sync(state: &AppState, args: &SyncArgs) -> Result<(), CliError> {
    let cfg = state.load_config()?;
    let store_box = build_store(&cfg, state)?;
    let store = &store_box;
    let secret_store = state.secret_store();
    let id = state.load_identity(&secret_store)?;
    let device = DeviceId::new(cfg.identity.device_id.clone());
    let platform = detect_platform();
    let home = home_dir();
    let host = hostname();
    let files = state.managed_files(&cfg, platform, &home, &host)?;

    // Load or seed the local manifest.
    let mut local = load_local_manifest(state, &device);

    // Resolver: interactive unless --non-interactive.
    let report = if args.non_interactive {
        let ctx = cs_sync::SyncContext {
            device: &device,
            files: &files,
            recip_keys: &id.recipient_keys,
            recip_secrets: &id.recipient_secrets,
            resolver: None,
            now: std::time::SystemTime::now(),
        };
        cs_sync::sync(store, &mut local, &ctx).await?
    } else {
        #[cfg(feature = "terminal")]
        {
            let term = cs_ui::TerminalInteractive::new();
            let resolver = cs_ui::InteractiveResolver::new(&term);
            let ctx = cs_sync::SyncContext {
                device: &device,
                files: &files,
                recip_keys: &id.recipient_keys,
                recip_secrets: &id.recipient_secrets,
                resolver: Some(&resolver),
                now: std::time::SystemTime::now(),
            };
            cs_sync::sync(store, &mut local, &ctx).await?
        }
        #[cfg(not(feature = "terminal"))]
        {
            let ctx = cs_sync::SyncContext {
                device: &device,
                files: &files,
                recip_keys: &id.recipient_keys,
                recip_secrets: &id.recipient_secrets,
                resolver: None,
                now: std::time::SystemTime::now(),
            };
            cs_sync::sync(store, &mut local, &ctx).await?
        }
    };
    save_local_manifest(state, &local)?;
    println!(
        "Sync complete: {} pulled, {} pushed, {} conflicts resolved{}.",
        report.pulled.len(),
        report.pushed.len(),
        report.conflicts_resolved.len(),
        if report.aborted {
            " (aborted by user)"
        } else {
            ""
        }
    );
    Ok(())
}

fn cmd_recover(state: &AppState, args: &RecoverArgs) -> Result<(), CliError> {
    let provider = args.provider.provider.as_str();
    let id = match provider {
        "mnemonic" => {
            let words = read_line("Enter your 24-word recovery mnemonic: ")?;
            let mp = cs_keys::MnemonicProvider::production();
            // Recover needs a bundle; for the CLI we expect one stored alongside
            // the config (recovery/mnemonic.bundle). Read it, then recover.
            let bundle_bytes = std::fs::read(state.config_dir.join("recovery/mnemonic.bundle"))
                .map_err(|_| {
                    CliError::Plain("no recovery bundle at recovery/mnemonic.bundle".into())
                })?;
            let bundle: cs_keys::RecoveryBundle = postcard::from_bytes(&bundle_bytes)
                .map_err(|e| CliError::Plain(format!("bundle decode: {e}")))?;
            let rik = mp
                .recover_with_mnemonic(&bundle, &words)
                .map_err(|e| CliError::Plain(format!("recovery failed: {e}")))?;
            DeviceIdentity::with_rik(cs_crypto::Rik::from_bytes(rik))
        }
        "cloud" => {
            let pass = read_line("Enter your recovery passphrase: ")?;
            let bundle_bytes = std::fs::read(state.config_dir.join("recovery/cloud.bundle"))
                .map_err(|_| {
                    CliError::Plain("no recovery bundle at recovery/cloud.bundle".into())
                })?;
            let bundle: cs_keys::RecoveryBundle = postcard::from_bytes(&bundle_bytes)
                .map_err(|e| CliError::Plain(format!("bundle decode: {e}")))?;
            let cp = cs_keys::CloudBundleProvider::production();
            let rik = cp
                .recover_with_passphrase(&bundle, &pass)
                .map_err(|e| CliError::Plain(format!("recovery failed: {e}")))?;
            DeviceIdentity::with_rik(cs_crypto::Rik::from_bytes(rik))
        }
        "shamir" => {
            return Err(CliError::Plain(
                "Shamir recovery is interactive; collect k shares and use the library API for now."
                    .into(),
            ));
        }
        other => {
            return Err(CliError::Plain(format!(
                "unknown recovery provider '{other}' (expected mnemonic|shamir|cloud)"
            )));
        }
    };
    let store = state.secret_store();
    state.store_identity(&store, &id)?;
    println!(
        "Recovered device identity and stored it in {}.",
        store_kind(&store)
    );
    Ok(())
}

fn cmd_doctor(state: &AppState) -> Result<(), CliError> {
    let mut ok = true;
    match state.load_config() {
        Ok(cfg) => println!(
            "[ok] config at {} (schema v{}, {} config(s))",
            state.config_path.display(),
            cfg.schema_version,
            cfg.configs.len()
        ),
        Err(e) => {
            println!("[fail] config: {e}");
            ok = false;
        }
    }
    let store = state.secret_store();
    match state.load_identity(&store) {
        Ok(_) => println!("[ok] device identity in {}", store_kind(&store)),
        Err(e) => {
            println!("[fail] identity: {e}");
            ok = false;
        }
    }
    match std::fs::metadata(&state.store_dir) {
        Ok(_) => println!("[ok] store dir at {}", state.store_dir.display()),
        Err(_) => println!(
            "[warn] store dir {} not present yet (created on first sync)",
            state.store_dir.display()
        ),
    }
    println!("[info] platform = {}", platform_to_str(detect_platform()));
    if ok {
        println!("config-sync looks healthy.");
    } else {
        return Err(CliError::Plain("doctor reported problems".into()));
    }
    Ok(())
}

// ---- helpers --------------------------------------------------------------

fn parse_policy(s: &str) -> Result<ConflictPolicy, CliError> {
    match s {
        "latest-wins" => Ok(ConflictPolicy::LatestWins),
        "prompt" => Ok(ConflictPolicy::Prompt),
        "manual" => Ok(ConflictPolicy::Manual),
        other => Err(CliError::Plain(format!(
            "unknown policy '{other}' (expected latest-wins|prompt|manual)"
        ))),
    }
}

fn policy_str(p: ConflictPolicy) -> &'static str {
    match p {
        ConflictPolicy::LatestWins => "latest-wins",
        ConflictPolicy::Prompt => "prompt",
        ConflictPolicy::Manual => "manual",
    }
}

fn store_kind(store: &crate::state::AppStore) -> &'static str {
    match store {
        crate::state::AppStore::File(_) => "local file",
        #[cfg(feature = "keyring-store")]
        crate::state::AppStore::Keyring(_) => "OS keychain",
        #[cfg(feature = "biometric")]
        crate::state::AppStore::Biometric(b) => {
            if b.is_biometric_gated() {
                "biometric-gated keychain"
            } else {
                "OS keychain (biometrics unavailable on this platform)"
            }
        }
    }
}

fn detect_platform() -> cs_config::Platform {
    #[cfg(target_os = "macos")]
    {
        cs_config::Platform::Mac
    }
    #[cfg(target_os = "windows")]
    {
        cs_config::Platform::Windows
    }
    #[cfg(target_os = "linux")]
    {
        cs_config::Platform::Linux
    }
    #[cfg(target_os = "freebsd")]
    {
        cs_config::Platform::FreeBSD
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux",
        target_os = "freebsd"
    )))]
    {
        cs_config::Platform::Linux
    }
}

fn home_dir() -> String {
    dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| std::env::var("HOME").unwrap_or_default())
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

fn read_line(prompt: &str) -> Result<String, CliError> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .map_err(|e| CliError::Plain(format!("read input: {e}")))?;
    Ok(buf.trim().to_string())
}

/// Local manifest is cached at `<config_dir>/manifest.bin` (postcard).
fn local_manifest_path(state: &AppState) -> std::path::PathBuf {
    state.config_dir.join("manifest.bin")
}

fn load_local_manifest(state: &AppState, device: &DeviceId) -> Manifest {
    match std::fs::read(local_manifest_path(state)) {
        Ok(b) => Manifest::from_bytes(&b).unwrap_or_else(|_| Manifest::new(device.as_str())),
        Err(_) => Manifest::new(device.as_str()),
    }
}

fn save_local_manifest(state: &AppState, m: &Manifest) -> Result<(), CliError> {
    let bytes = m
        .to_bytes()
        .map_err(|e| CliError::Plain(format!("manifest encode: {e}")))?;
    std::fs::write(local_manifest_path(state), bytes)?;
    Ok(())
}
