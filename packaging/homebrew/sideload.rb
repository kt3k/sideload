require "formula"

class Sideload < Formula
  desc "Sideload iOS apps onto a device with an Apple developer account"
  homepage "https://github.com/kt3k/sideload"
  license "MIT"
  head "https://github.com/kt3k/sideload.git", branch: "main"

  # Stable release: fill in at each tag. Get the checksum with
  #   curl -fsSL https://github.com/kt3k/sideload/archive/refs/tags/v0.1.6.tar.gz | shasum -a 256
  url "https://github.com/kt3k/sideload/archive/refs/tags/v0.1.6.tar.gz"
  sha256 "420e1ca4250816e741d6c57ddfc5b7e2ee3c5e0a9aab8e1285850302589eccab"
  version "0.1.6"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    <<~EOF
      To talk to a device you also need the USB multiplexer:
        - macOS: built in, nothing to install
        - Linux: install usbmuxd

      Anisette is generated locally with the system AOSKit/AuthKit frameworks.
      If that fails, pass a remote server: sideload --anisette-server <URL> ...
    EOF
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sideload version")
    assert_match "Usage:", shell_output("#{bin}/sideload --help")
  end
end
