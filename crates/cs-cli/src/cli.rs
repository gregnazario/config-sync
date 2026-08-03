//! Command-line argument definitions (clap derive).

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "config-sync",
    version,
    about = "Sync config files across machines with post-quantum E2E encryption"
)]
pub struct Cli {
    /// Override the config directory (defaults to ~/.config/config-sync on
    /// Unix, %APPDATA%/config-sync on Windows).
    #[arg(long, global = true)]
    pub config_dir: Option<std::path::PathBuf>,

    /// Disable biometric gating for the device identity (use the plain
    /// keychain / file store instead of Touch ID / Windows Hello).
    #[arg(long, global = true, default_value_t = false)]
    pub no_biometrics: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialize config-sync on this device: generate a device identity and
    /// write a starter config.
    Init(InitArgs),
    /// Register a config file to sync (added to the local config).
    Add(AddArgs),
    /// List managed configs.
    List,
    /// Push and pull changes to/from the remote store, resolving conflicts.
    Sync(SyncArgs),
    /// Recover the device identity from a recovery provider (mnemonic / cloud).
    Recover(RecoverArgs),
    /// Diagnose the local environment: config presence, identity, store.
    Doctor,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Hostname to record for this device (defaults to the machine hostname).
    #[arg(long)]
    pub host: Option<String>,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// A friendly name for this config set (e.g. "vim").
    pub name: String,
    /// Path to the file to manage (e.g. ~/.vimrc).
    pub path: String,
    /// Conflict policy: latest-wins | prompt | manual.
    #[arg(long, default_value = "latest-wins")]
    pub policy: String,
}

#[derive(Args, Debug)]
pub struct SyncArgs {
    /// Run without interactive prompts; conflicts use the per-set policy.
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Args, Debug)]
pub struct RecoveryProviderArg {
    /// Which recovery provider: mnemonic | shamir | cloud.
    #[arg(long)]
    pub provider: String,
}
#[derive(Args, Debug)]
pub struct RecoverArgs {
    #[command(flatten)]
    pub provider: RecoveryProviderArg,
}
