class Magicrune < Formula
  desc "Secure code execution framework with automatic sandbox detection"
  homepage "https://github.com/magicrune/magicrune"
  version "0.1.0"
  license "MIT"

  if Hardware::CPU.intel?
    url "https://github.com/magicrune/magicrune/releases/download/v0.1.0/magicrune-x86_64-apple-darwin.tar.gz"
    sha256 "PLACEHOLDER_SHA256_INTEL"
  elsif Hardware::CPU.arm?
    url "https://github.com/magicrune/magicrune/releases/download/v0.1.0/magicrune-aarch64-apple-darwin.tar.gz"
    sha256 "PLACEHOLDER_SHA256_ARM64"
  end

  def install
    bin.install "magicrune"
    
    # Create default directories
    (var/"magicrune/trusted_keys").mkpath
    (var/"magicrune/audit").mkpath
    (var/"magicrune/cache").mkpath
    
    # Install completion scripts if available
    bash_completion.install "completions/magicrune.bash" if File.exist?("completions/magicrune.bash")
    zsh_completion.install "completions/_magicrune" if File.exist?("completions/_magicrune")
    fish_completion.install "completions/magicrune.fish" if File.exist?("completions/magicrune.fish")
  end

  test do
    system "#{bin}/magicrune", "--version"
    system "#{bin}/magicrune", "--help"
  end
end