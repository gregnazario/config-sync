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
    // A half-initialized state (identity without config) must not be silently
    // re-keyed: that would strand every blob sealed under the old identity.
    {
        let probe = state.secret_store();
        if state.identity_exists(&probe) {
            return Err(CliError::Plain(format!(
                "an identity already exists in {} but no config was found; \
                 remove the identity knowingly before re-initializing",
                store_kind(&probe)
            )));
        }
    }
    let host = args.host.clone().unwrap_or_else(hostname);
    let mut cfg = AppState::starter_config(&host);
    // Generate a device identity and persist it.
    let id = cs_keys::DeviceIdentity::new()
        .map_err(|e| CliError::Plain(format!("identity generation: {e}")))?;
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
         RIK fingerprint: {}\n\
         Record this fingerprint somewhere safe: recovery verifies against it, and a\n\
         mismatch means the recovered key is not yours.\n\
         Add files with `config-sync add <name> <path>`, then `config-sync sync`.",
        state.config_dir.display(),
        cfg.identity.device_id,
        store_kind(&store),
        cs_keys::rik_fingerprint(id.rik.as_bytes()),
    );
    // Mark cfg used so the unused-mut warning stays accurate.
    let _ = &mut cfg;
    Ok(())
}

fn cmd_add(state: &AppState, args: &AddArgs) -> Result<(), CliError> {
    let mut cfg = state.load_config()?;
    let policy = parse_policy(&args.policy)?;
    if !cs_config::is_absolute_ish(&args.path) {
        return Err(CliError::Plain(format!(
            "path '{}' must be absolute (start with ~/, /, a drive letter, or %VAR%)",
            args.path
        )));
    }
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
    let manifest_signer = cs_crypto::ManifestSigningKey::derive_from_rik(&id.rik);
    let device = DeviceId::new(cfg.identity.device_id.clone());
    let platform = detect_platform();
    let home = home_dir();
    let host = hostname();
    let files = state.managed_files(&cfg, platform, &home, &host)?;

    // Load or seed the local manifest (bound to this vault).
    let vault_fingerprint = cs_keys::rik_fingerprint(id.rik.as_bytes());
    let mut local = load_local_manifest(state, &device, &vault_fingerprint)?;

    // Resolver: interactive unless --non-interactive.
    let report = if args.non_interactive {
        let ctx = cs_sync::SyncContext {
            device: &device,
            files: &files,
            recip_keys: &id.recipient_keys,
            recip_secrets: &id.recipient_secrets,
            manifest_signer: &manifest_signer,
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
                manifest_signer: &manifest_signer,
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
                manifest_signer: &manifest_signer,
                resolver: None,
                now: std::time::SystemTime::now(),
            };
            cs_sync::sync(store, &mut local, &ctx).await?
        }
    };
    save_local_manifest(state, &local, &vault_fingerprint)?;
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
    if args.setup {
        return recovery_setup(state, args);
    }
    let provider = args.provider.provider.as_str();
    let (rik, fingerprint_hint) = match provider {
        "mnemonic" => {
            let words = read_secret("Enter your 24-word recovery mnemonic")?;
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
                .recover_with_mnemonic(&bundle, &words, None)
                .map_err(|e| CliError::Plain(format!("recovery failed: {e}")))?;
            (rik, None)
        }
        "cloud" => {
            let pass = read_secret("Enter your recovery passphrase")?;
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
            (rik, None)
        }
        "shamir" => recover_from_shamir()?,
        other => {
            return Err(CliError::Plain(format!(
                "unknown recovery provider '{other}' (expected mnemonic|shamir|cloud)"
            )));
        }
    };

    let fingerprint = cs_keys::rik_fingerprint(&rik);
    println!("Recovered RIK fingerprint: {fingerprint}");
    if let Some(expected) = fingerprint_hint.as_deref() {
        if !expected.eq_ignore_ascii_case(&fingerprint) {
            return Err(CliError::Plain(format!(
                "fingerprint mismatch: shares reconstructed a key with fingerprint \
                 {fingerprint}, but the recorded fingerprint is {expected}. \
                 The shares may have been substituted or tampered — refusing to \
                 install this identity."
            )));
        }
        println!("[ok] fingerprint matches the seal-time record.");
    } else {
        println!(
            "Verify this against the fingerprint recorded when recovery was set up \
             (write it down now if you haven't)."
        );
    }

    let id = DeviceIdentity::from_rik(cs_crypto::Rik::from_bytes(rik));

    // Never silently replace a working identity: the previous RIK is the only
    // key to every existing blob. Confirm interactively and keep a backup.
    let store = state.secret_store();
    if state.identity_exists(&store) {
        let answer = read_line(
            "An identity ALREADY exists on this device. Replacing it loses access to \
             anything sealed under the old key if no backup exists. Continue? [y/N]",
        )?;
        if !answer.eq_ignore_ascii_case("y") {
            return Err(CliError::Plain(
                "recovery aborted; existing identity kept".into(),
            ));
        }
        if let Ok(old_bytes) = store.get(crate::state::IDENTITY_ACCOUNT) {
            let backup = state.config_dir.join("identity.backup.bin");
            crate::state::secure_write(&backup, &old_bytes)?;
            println!("Previous identity backed up to {}.", backup.display());
        }
    }
    state.store_identity(&store, &id)?;
    println!(
        "Recovered device identity (recipient keys re-derived from the RIK — existing \
         vault data is decryptable) and stored it in {}.",
        store_kind(&store)
    );
    Ok(())
}

/// Interactive k-of-n Shamir recovery: collect the threshold and the shares
/// from stdin (one hex-encoded share per line), plus the optional — but
/// strongly recommended — fingerprint recorded at seal time.
fn recover_from_shamir() -> Result<([u8; 32], Option<String>), CliError> {
    let threshold: u8 = read_line("Enter the share threshold k for this vault")?
        .parse()
        .map_err(|_| CliError::Plain("threshold must be a small number (e.g. 2)".into()))?;
    if threshold < 1 {
        return Err(CliError::Plain("threshold must be at least 1".into()));
    }
    println!("Enter {threshold} shares, one per line (hex, as produced at seal time):");
    let mut shares = Vec::new();
    while shares.len() < threshold as usize {
        // Shares are secrets: a full threshold reconstructs the RIK, so they
        // are read with echo suppression like any other secret.
        let line = read_secret(&format!("  share {}/{}", shares.len() + 1, threshold))?;
        if line.trim().is_empty() {
            continue;
        }
        let data = hex::decode(line.trim())
            .map_err(|e| CliError::Plain(format!("share is not valid hex: {e}")))?;
        let index = *data.first().ok_or_else(|| {
            CliError::Plain("share is empty; a share starts with its index byte".into())
        })?;
        shares.push(cs_keys::ShamirShare { index, data });
    }
    let expected = {
        let fp = read_line(
            "Enter the RIK fingerprint recorded at seal time (recommended; empty to skip \
             verification)",
        )?;
        if fp.trim().is_empty() {
            println!(
                "[warn] proceeding WITHOUT fingerprint verification — a substituted set of \
                 shares cannot be detected. Record the fingerprint printed next."
            );
            None
        } else {
            Some(fp.trim().to_ascii_lowercase())
        }
    };
    let provider = cs_keys::ShamirProvider::new(threshold, threshold);
    let rik = provider
        .recombine(&shares, expected.as_deref())
        .map_err(|e| CliError::Plain(format!("shamir recovery failed: {e}")))?;
    Ok((rik, expected))
}

/// Create recovery material for this vault's RIK (`config-sync recover
/// --provider X --setup`). Closes the loop on the recovery promise: without
/// this, `recover` could only ever fail with "no recovery bundle".
fn recovery_setup(state: &AppState, args: &RecoverArgs) -> Result<(), CliError> {
    let store = state.secret_store();
    let id = state.load_identity(&store)?;
    let rik_bytes = *id.rik.as_bytes();
    let fingerprint = cs_keys::rik_fingerprint(&rik_bytes);
    println!("Vault RIK fingerprint: {fingerprint}");
    println!("Record it now — recovery verifies against it.\n");

    let recovery_dir = state.config_dir.join("recovery");
    match args.provider.provider.as_str() {
        "mnemonic" => {
            let mp = cs_keys::MnemonicProvider::production();
            let sealed = mp
                .seal_with_mnemonic(&rik_bytes, None)
                .map_err(|e| CliError::Plain(format!("mnemonic seal: {e}")))?;
            let bundle_bytes = postcard::to_allocvec(&sealed.bundle)
                .map_err(|e| CliError::Plain(format!("bundle encode: {e}")))?;
            let path = recovery_dir.join("mnemonic.bundle");
            crate::state::secure_write(&path, &bundle_bytes)?;
            println!(
                "Recovery mnemonic (write it down NOW — it is shown ONCE and never stored):\n\n  {}\n",
                sealed.mnemonic_words
            );
            println!("Recovery bundle written to {}.", path.display());
        }
        "cloud" => {
            let pass = read_secret("Choose a recovery passphrase (min 12 chars)")?;
            let confirm = read_secret("Confirm the passphrase")?;
            if pass != confirm {
                return Err(CliError::Plain("passphrases do not match".into()));
            }
            let cp = cs_keys::CloudBundleProvider::production();
            let bundle = cp
                .seal_with_passphrase(&rik_bytes, &pass)
                .map_err(|e| CliError::Plain(format!("cloud seal: {e}")))?;
            let bundle_bytes = postcard::to_allocvec(&bundle)
                .map_err(|e| CliError::Plain(format!("bundle encode: {e}")))?;
            let path = recovery_dir.join("cloud.bundle");
            crate::state::secure_write(&path, &bundle_bytes)?;
            println!("Recovery bundle written to {}.", path.display());
            println!("Upload it to any store you can reach when recovering.");
        }
        "shamir" => {
            let k: u8 = {
                let s = read_line("Threshold k (default 2)")?;
                if s.trim().is_empty() {
                    2
                } else {
                    s.trim()
                        .parse()
                        .map_err(|_| CliError::Plain("k must be a number".into()))?
                }
            };
            let n: u8 = {
                let s = read_line("Share count n (default 3)")?;
                if s.trim().is_empty() {
                    3
                } else {
                    s.trim()
                        .parse()
                        .map_err(|_| CliError::Plain("n must be a number".into()))?
                }
            };
            if k < 1 || n < k {
                return Err(CliError::Plain("need 1 <= k <= n".into()));
            }
            let provider = cs_keys::ShamirProvider::new(k, n);
            let split = provider
                .split(&rik_bytes)
                .map_err(|e| CliError::Plain(format!("shamir split: {e}")))?;
            println!("Store each share in a DIFFERENT location (devices, providers, paper):\n");
            for share in &split.shares {
                println!("  share {}: {}", share.index, hex::encode(&share.data));
            }
            println!(
                "\nFingerprint for recovery verification: {fingerprint} \
                 (pass it to `recover --provider shamir` when prompted)."
            );
            println!("No share data is written to disk — the shares exist only above.");
        }
        other => {
            return Err(CliError::Plain(format!(
                "unknown recovery provider '{other}' (expected mnemonic|shamir|cloud)"
            )));
        }
    }
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
    // Read the hostname directly from the system instead of spawning a subprocess.
    #[cfg(unix)]
    {
        use std::sync::OnceLock;
        static HOSTNAME: OnceLock<String> = OnceLock::new();
        HOSTNAME
            .get_or_init(|| {
                // Try /etc/hostname, then HOSTNAME env, then fall back.
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .or_else(|| std::env::var("HOSTNAME").ok())
                    .unwrap_or_else(|| "unknown".to_string())
            })
            .clone()
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

/// Read a secret (mnemonic, passphrase) with echo suppressed when attached to
/// a terminal; falls back to plain stdin for headless use. Secrets must not
/// land in terminal scrollback or session logs.
fn read_secret(prompt: &str) -> Result<String, CliError> {
    #[cfg(feature = "terminal")]
    {
        let term = console::Term::stderr();
        if term.is_term() {
            return dialoguer::Password::new()
                .with_prompt(prompt)
                .report(false)
                .interact_on(&term)
                .map_err(|e| CliError::Plain(format!("read secret: {e}")));
        }
    }
    read_line(&format!("{prompt}: "))
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

/// The cache is bound to the vault's RIK fingerprint (`CSLM1` header) so a
/// manifest copied from another vault fails loudly; legacy headerless caches
/// still load (and are re-saved with the binding).
fn load_local_manifest(
    state: &AppState,
    device: &DeviceId,
    vault_fingerprint: &str,
) -> Result<Manifest, CliError> {
    match std::fs::read(local_manifest_path(state)) {
        Ok(b) => {
            let payload = strip_or_verify_cache_header(&b, vault_fingerprint)?;
            Manifest::from_bytes(payload).map_err(|e| {
                // Fail loudly: silently reseeding from empty would forget every
                // vector clock and tombstone, resurrect deleted files, and accept
                // any (even rolled-back) remote state as fresh.
                CliError::Plain(format!(
                    "local manifest at {} is corrupt ({e}); restore it from a backup or \
                 remove it knowingly to re-seed",
                    local_manifest_path(state).display()
                ))
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Manifest::new(device.as_str())),
        Err(e) => Err(e.into()),
    }
}

/// If the cache carries a `CSLM1` fingerprint header, verify it against this
/// vault and return the payload; legacy headerless caches return as-is.
fn strip_or_verify_cache_header<'a>(
    b: &'a [u8],
    vault_fingerprint: &str,
) -> Result<&'a [u8], CliError> {
    if b.starts_with(MANIFEST_CACHE_MAGIC) && b.len() > 5 + 16 {
        let stored = String::from_utf8_lossy(&b[5..5 + 16]).into_owned();
        if !stored.trim().eq_ignore_ascii_case(vault_fingerprint) {
            return Err(CliError::Plain(
                "the local manifest cache belongs to a DIFFERENT vault; remove it \
                 knowingly to re-seed"
                    .into(),
            ));
        }
        Ok(&b[5 + 16..])
    } else {
        Ok(b)
    }
}

const MANIFEST_CACHE_MAGIC: &[u8; 5] = b"CSLM1";

fn save_local_manifest(
    state: &AppState,
    m: &Manifest,
    vault_fingerprint: &str,
) -> Result<(), CliError> {
    let body = m
        .to_bytes()
        .map_err(|e| CliError::Plain(format!("manifest encode: {e}")))?;
    let mut bytes = Vec::with_capacity(5 + 16 + body.len());
    bytes.extend_from_slice(MANIFEST_CACHE_MAGIC);
    let fp = format!("{vault_fingerprint:<16}");
    bytes.extend_from_slice(&fp.as_bytes()[..16]);
    bytes.extend_from_slice(&body);
    // Atomic + 0600: the manifest inventories every synced file (hashes,
    // sizes, paths) and a torn write would brick the next sync.
    crate::state::secure_write(&local_manifest_path(state), &bytes)
}
