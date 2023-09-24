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
	afl-fuzz -i sample -o fuzz-url -O -g 0 -G 512 -- $?

.PHONY: fuzz-urn-console
fuzz-urn-console: zig-out/bin/fuzz-urn
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-urn -O -g 0 -G 64 -- $?

.PHONY: fuzz-urview-console
fuzz-urview-console: zig-out/bin/fuzz-urview
	afl-fuzz -i sample -o fuzz-urview -O -g 0 -G 64 -- $?


.PHONY: fmt
fmt: *.zig
	zig $@ $?

.PHONY: dist
dist: test fmt zig-out test-samples Urlink-doc Urname-doc Urview-doc

# TODO(pascaldekloe): Replace in build.zig pending
# <https://github.com/ziglang/zig/issues/16866>.
.PHONY: test-samples
test-samples: zig-out/bin/fuzz-urview zig-out/bin/fuzz-url zig-out/bin/fuzz-urn
	./zig-out/bin/fuzz-urview < sample/bloat
	./zig-out/bin/fuzz-urview < sample/empty
	./zig-out/bin/fuzz-urview < sample/tricky
	./zig-out/bin/fuzz-urview < /dev/null
	./zig-out/bin/fuzz-url < /dev/null
	./zig-out/bin/fuzz-urn < /dev/null
	./zig-out/bin/fuzz-urview < /dev/zero
	./zig-out/bin/fuzz-url < /dev/zero
	./zig-out/bin/fuzz-urn < /dev/zero

.PHONY: clean
clean:
	rm -fr zig-cache zig-out
	rm -fr Urlink-doc Urname-doc Urview-doc
	rm -f bench.asm
	rm -f demo

.PHONY: install
install: zig-out/lib/libzuri.a zuri-config.cmake
	install -o 0 -g 0 -m 755 -d $(PREFIX)/include
	install -o 0 -g 0 -m 644 zuri.h $(PREFIX)/include
	install -o 0 -g 0 -m 755 -d $(PREFIX)/lib/cmake/zuri
	install -o 0 -g 0 -m 644 zig-out/lib/libzuri.a $(PREFIX)/lib
	install -o 0 -g 0 -m 644 zuri-config.cmake $(PREFIX)/lib/cmake/zuri

.PHONY: uninstall
uninstall:
	rm -fi $(PREFIX)/include/zuri.h
	rm -fi $(PREFIX)/lib/libzuri.a
	rm -fir $(PREFIX)/lib/cmake/zuri


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
