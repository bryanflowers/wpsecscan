# Homebrew formula for WPSecScan
# Install: brew install bryanflowers/tap/wpsecscan
# Tap location: github.com/bryanflowers/homebrew-tap (you must create this repo)

class Wpsecscan < Formula
  desc "Defensive WordPress security scanner — 150+ checks, runs locally"
  homepage "https://github.com/bryanflowers/wpsecscan"
  url "https://github.com/bryanflowers/wpsecscan/archive/refs/tags/v2.1.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
  license "AGPL-3.0-or-later"
  head "https://github.com/bryanflowers/wpsecscan.git", branch: "main"

  depends_on "python@3.12"

  def install
    venv = virtualenv_create(libexec, "python3.12")
    venv.pip_install_and_link buildpath
    # Optional: install man page
    man1.install "wpsecscan.1" if File.exist?("wpsecscan.1")
  end

  test do
    assert_match "wpsecscan 2.", shell_output("#{bin}/wpsecscan --version")
  end
end
