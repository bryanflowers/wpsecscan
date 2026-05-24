# Round-64 #107 — Homebrew formula scaffold
class Wpsecscan < Formula
  include Language::Python::Virtualenv

  desc "Defensive WordPress security scanner"
  homepage "https://github.com/bryanflowers/wpsecscan"
  url "https://github.com/bryanflowers/wpsecscan/archive/refs/tags/v2.2.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_FROM_RELEASE"
  license "AGPL-3.0-or-later"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "WPSecScan", shell_output("#{bin}/wpsecscan --version")
  end
end
