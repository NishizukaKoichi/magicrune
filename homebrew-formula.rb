class Magicrune < Formula
  desc "Secure code execution framework with automatic sandbox detection"
  homepage "https://github.com/magicrune/magicrune"
  version "0.2.1"
  license "MIT"

  if Hardware::CPU.intel?
    url "https://github.com/magicrune/magicrune/releases/download/v0.2.1/magicrune-x86_64-apple-darwin.tar.gz"
    sha256 "0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5"
  elsif Hardware::CPU.arm?
    url "https://github.com/magicrune/magicrune/releases/download/v0.2.1/magicrune-aarch64-apple-darwin.tar.gz"
    sha256 "0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5"
  end

  def install
    bin.install "magicrune"
    
    # Create default directories
    (var/"magicrune/trusted_keys").mkpath
    (var/"magicrune/audit").mkpath
    (var/"magicrune/cache").mkpath
  end

  test do
    system "#{bin}/magicrune", "--version"
    system "#{bin}/magicrune", "--help"
  end
end
