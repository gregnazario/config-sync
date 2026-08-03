# Homebrew Formula for config-sync
# Publish in a tap repo: github.com/gregnazario/homebrew-config-sync
# Install: brew tap gregnazario/config-sync && brew install config-sync
class ConfigSync < Formula
  desc "Sync config files across machines with post-quantum E2E encryption"
  homepage "https://github.com/gregnazario/config-sync"
  version "0.1.0"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/gregnazario/config-sync/releases/download/v#{version}/config-sync-aarch64-apple-darwin-v#{version}.tar.gz"
      sha256 "PLACEHOLDER_ARM_MACOS_SHA256"
    end
    on_intel do
      url "https://github.com/gregnazario/config-sync/releases/download/v#{version}/config-sync-x86_64-apple-darwin-v#{version}.tar.gz"
      sha256 "PLACEHOLDER_X86_MACOS_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/gregnazario/config-sync/releases/download/v#{version}/config-sync-aarch64-unknown-linux-gnu-v#{version}.tar.gz"
      sha256 "PLACEHOLDER_ARM_LINUX_SHA256"
    end
    on_intel do
      url "https://github.com/gregnazario/config-sync/releases/download/v#{version}/config-sync-x86_64-unknown-linux-gnu-v#{version}.tar.gz"
      sha256 "PLACEHOLDER_X86_LINUX_SHA256"
    end
  end

  def install
    bin.install "config-sync"
  end

  test do
    assert_match "config-sync", shell_output("#{bin}/config-sync --version")
  end
end
