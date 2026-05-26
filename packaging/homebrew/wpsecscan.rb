# Item #65 — Homebrew formula for wpsecscan.
#
# Tap-and-install workflow:
#   brew tap bryanflowers/wpsecscan
#   brew install wpsecscan
#
# This formula vends the Python entry point through a virtualenv (the
# standard Homebrew approach for Python apps) so it doesn't collide with
# the user's system Python. Update the `url` + `sha256` on each release.

class Wpsecscan < Formula
  include Language::Python::Virtualenv

  desc "Defensive WordPress security scanner (authorized testing only)"
  homepage "https://github.com/bryanflowers/wpsecscan"
  url "https://github.com/bryanflowers/wpsecscan/archive/refs/tags/vX.Y.Z.tar.gz"
  sha256 "REPLACE_ON_EACH_RELEASE_WITH_THE_TARBALL_SHA256"
  license "MIT"

  depends_on "python@3.12"
  depends_on "openssl@3"

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/source/h/httpx/httpx-0.27.0.tar.gz"
    sha256 "REPLACE_WITH_SDIST_SHA256"
  end

  resource "jinja2" do
    url "https://files.pythonhosted.org/packages/source/J/Jinja2/Jinja2-3.1.4.tar.gz"
    sha256 "REPLACE_WITH_SDIST_SHA256"
  end

  # Add other resource blocks per dep listed in pyproject.toml. Use
  # `brew update-python-resources Formula/wpsecscan.rb` to refresh.

  def install
    virtualenv_install_with_resources
  end

  test do
    system bin/"wpsecscan", "--version"
  end
end
