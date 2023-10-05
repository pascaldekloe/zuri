# installation location
PREFIX ?= /usr/local

.PHONY: test
test: demo
	zig build test
	./demo

demo: demo.c zig-out/lib/libzuri.a zuri.h
	zig build
	clang -o $@ -Lzig-out/lib -l zuri demo.c

.PHONY: bench
bench: zig-out/bin/bench
	# warmup round; errors report to standard error
	$? > /dev/null
	$?


bench.asm: Urlink.zig Urname.zig Urview.zig bench.zig
	zig build-exe -O ReleaseFast -femit-asm=$@ -fno-emit-bin -fstrip bench.zig

Urlink-doc: Urlink.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

Urname-doc: Urname.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

Urview-doc: Urview.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?


.PHONY: fuzz-url-console
fuzz-url-console: zig-out/bin/fuzz-url
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-url-out -O -g 0 -G 512 -- $?

.PHONY: fuzz-urn-console
fuzz-urn-console: zig-out/bin/fuzz-urn
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-urn-out -O -g 0 -G 64 -- $?

.PHONY: fuzz-urview-console
fuzz-urview-console: zig-out/bin/fuzz-urview
	afl-fuzz -i sample -o fuzz-urview-out -O -g 0 -G 64 -- $?


.PHONY: fmt
fmt: *.zig
	zig $@ $?

.PHONY: dist
dist: test fmt zig-out Urlink-doc Urname-doc Urview-doc

.PHONY: clean
clean:
	rm -fr zig-cache zig-out
	rm -fr Urlink-doc Urname-doc Urview-doc
	rm -f bench.asm
	rm -f demo
	rm -fr dist/

.PHONY: install
install: zig-out/lib/libzuri.a
	install -m 755 -d $(PREFIX)/include
	install -m 644 zuri.h $(PREFIX)/include
	install -m 755 -d $(PREFIX)/lib/cmake/zuri
	install -m 644 zig-out/lib/libzuri.a $(PREFIX)/lib
	install -m 644 package/zuri-config.cmake $(PREFIX)/lib/cmake/zuri

.PHONY: uninstall
uninstall:
	rm -fi $(PREFIX)/include/zuri.h
	rm -fi $(PREFIX)/lib/libzuri.a
	rm -fir $(PREFIX)/lib/cmake/zuri

dist/linux-amd64.deb: zig-out/lib/liblinux-amd64.a
	# header
	install -m 755 -d dist/linux-amd64/usr/local/include
	install -m 644 zuri.h dist/linux-amd64/usr/local/include
	# static library
	install -m 755 -d dist/linux-amd64/usr/local/lib
	install -m 644 $? dist/linux-amd64/usr/local/lib
	# CMake configuration
	install -m 755 -d dist/linux-amd64/usr/local/lib/cmake/zuri
	install -m 644 package/zuri-config.cmake dist/linux-amd64/usr/local/lib/cmake/zuri
	# Debian package definition
	install -m 755 -d dist/linux-amd64/DEBIAN
	install -m 644 package/control dist/linux-amd64/DEBIAN
	echo "Architecture: amd64" >> dist/linux-amd64/DEBIAN/control
	echo "Source: zuri (`git describe --always`)" >> dist/linux-amd64/DEBIAN/control
	# build
	dpkg-deb --root-owner-group --build dist/linux-amd64

dist/linux-arm64.deb: zig-out/lib/liblinux-arm64.a
	# header
	install -m 755 -d dist/linux-arm64/usr/local/include
	install -m 644 zuri.h dist/linux-arm64/usr/local/include
	# static library
	install -m 755 -d dist/linux-arm64/usr/local/lib
	install -m 644 $? dist/linux-arm64/usr/local/lib
	# CMake configuration
	install -m 755 -d dist/linux-arm64/usr/local/lib/cmake/zuri
	install -m 644 package/zuri-config.cmake dist/linux-arm64/usr/local/lib/cmake/zuri
	# Debian package definition
	install -m 755 -d dist/linux-arm64/DEBIAN
	install -m 644 package/control dist/linux-arm64/DEBIAN
	echo "Architecture: arm64" >> dist/linux-arm64/DEBIAN/control
	echo "Source: zuri (`git describe --always`)" >> dist/linux-arm64/DEBIAN/control
	# build
	dpkg-deb --root-owner-group --build dist/linux-arm64


zig-out/bin/bench: *.zig
	zig build

zig-out/lib/libzuri.a: *.zig
	zig build

zig-out/bin/fuzz-urview: *.zig
	zig build

zig-out/bin/fuzz-url: *.zig
	zig build

zig-out/bin/fuzz-urn: *.zig
	zig build

zig-out/lib/liblinux-amd64.a: *.zig
	zig build

zig-out/lib/liblinux-arm64.a: *.zig
	zig build
