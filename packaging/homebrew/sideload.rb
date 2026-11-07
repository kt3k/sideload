# Homebrew formula for sideload, building from source.
#
# This is a template to copy into a tap repository named `kt3k/homebrew-tap`
# as `Formula/sideload.rb`. Users then install with:
#
#   brew install kt3k/tap/sideload
#
# For each release, update `url` to the release tarball and `sha256` to its
# checksum. Get the checksum with:
#
#   curl -fsSL https://github.com/kt3k/sideload/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256
#
class Sideload < Formula
  desc "Sideload iOS apps onto a device with an Apple developer account"
  homepage "https://github.com/kt3k/sideload"
  url "https://github.com/kt3k/sideload/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/kt3k/sideload.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sideload version")
    assert_match "Usage:", shell_output("#{bin}/sideload --help")
  end
end
