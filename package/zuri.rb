# Homebrew Formula
class Zuri < Formula
  desc "rich URI library"
  homepage "https://github.com/pascaldekloe/zuri"
  url "https://github.com/pascaldekloe/zuri/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "b4950487f995cc9a83e077de31d47a5b8c1d7e9a0c62836f269262dc03835e3c"
  license "CC0-1.0"
  head "https://github.com/pascaldekloe/zuri.git", branch: "master"

  depends_on "zig" => :build

  def install
    system "make", "install", "PREFIX=#{prefix}"
  end

  test do
	system ENV.cc, "-l", "zuri", pkgshare/"demo.c"
  end
end
