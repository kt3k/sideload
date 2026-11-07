require "formula"

class Sideload < Formula
  desc "Sideload iOS apps onto a device with an Apple developer account"
  homepage "https://github.com/kt3k/sideload"
  license "MIT"
  head "https://github.com/kt3k/sideload.git", branch: "main"

  # Stable release: fill in at each tag. Get the checksum with
  #   curl -fsSL https://github.com/kt3k/sideload/archive/refs/tags/v0.1.3.tar.gz | shasum -a 256
  url "https://github.com/kt3k/sideload/archive/refs/tags/v0.1.3.tar.gz"
  sha256 "db6385c4848a98a618f3b80ba984d7016d981652f9837b34d7a33e72000b09cd"
  version "0.1.3"

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
