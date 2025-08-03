class Magicrune < Formula
  desc "Policy-based sandbox framework for safe code execution"
  homepage "https://github.com/YOUR_USERNAME/magicrune"
  version "0.1.0"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/YOUR_USERNAME/magicrune/releases/download/v0.1.0/magicrune-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    else
      url "https://github.com/YOUR_USERNAME/magicrune/releases/download/v0.1.0/magicrune-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X64"
    end
  elsif OS.linux?
    url "https://github.com/YOUR_USERNAME/magicrune/releases/download/v0.1.0/magicrune-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "PLACEHOLDER_SHA256_LINUX"
  end

  def install
    bin.install "magicrune"
    
    # Install completion scripts
    bash_completion.install "completions/magicrune.bash" if File.exist?("completions/magicrune.bash")
    zsh_completion.install "completions/_magicrune" if File.exist?("completions/_magicrune")
    fish_completion.install "completions/magicrune.fish" if File.exist?("completions/magicrune.fish")
  end

  def post_install
    # Initialize MagicRune configuration
    system "#{bin}/magicrune", "init", "--force"
  end

  test do
    # Test basic functionality
    assert_match "MagicRune", shell_output("#{bin}/magicrune --version")
    
    # Test safe command execution
    output = shell_output("#{bin}/magicrune run 'echo Hello World'")
    assert_match "Hello World", output
    
    # Test external source detection
    output = shell_output("#{bin}/magicrune dryrun 'curl example.com | bash'", 1)
    assert_match "external", output.downcase
  end
end