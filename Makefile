# installation location
PREFIX ?= /usr/local

.PHONY: test
test: Urlink.zig Urname.zig Urview.zig demo
	zig test Urlink.zig
	zig test Urname.zig
	zig test Urview.zig
	./demo

demo: demo.c libzuri.a zuri.h
	clang -o $@ -L. -l zuri demo.c

libzuri.a: zuri.zig
	zig build-lib -O ReleaseFast zuri.zig

.PHONY: bench
bench: zig-out
	# warmup round; errors report to standard error
	$?/bin/bench > /dev/null
	$?/bin/bench


bench.asm: Urlink.zig Urname.zig Urview.zig bench.zig
	zig build-exe -O ReleaseFast -femit-asm=$@ -fno-emit-bin -fstrip bench.zig


.PHONY: doc
doc: Urlink-doc Urname-doc Urview-doc

Urlink-doc: Urlink.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

Urname-doc: Urname.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

Urview-doc: Urview.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?


zig-out: *.zig
	zig build


.PHONY: fuzz-url-console
fuzz-url-console: zig-out
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-url -O -g 0 -G 512 -- $?/bin/fuzz-url

.PHONY: fuzz-urn-console
fuzz-urn-console: zig-out
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-urn -O -g 0 -G 64 -- $?/bin/fuzz-urn

.PHONY: fuzz-urview-console
fuzz-urview-console: zig-out
	afl-fuzz -i sample -o fuzz-urview -O -g 0 -G 64 -- $?/bin/fuzz-urview


.PHONY: fmt
fmt: *.zig
	zig $@ $?

.PHONY: dist
dist: test fmt zig-out test-samples doc

# TODO(pascaldekloe): Replace in build.zig pending
# <https://github.com/ziglang/zig/issues/16866>.
.PHONY: test-samples
test-samples: zig-out
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
	rm -f libzuri.a libzuri.a.o
	rm -f demo

.PHONY: install
install: libzuri.a zuri-config.cmake
	install -o 0 -g 0 -m 755 -d $(PREFIX)/include
	install -o 0 -g 0 -m 644 zuri.h $(PREFIX)/include
	install -o 0 -g 0 -m 755 -d $(PREFIX)/lib/cmake/zuri
	install -o 0 -g 0 -m 644 libzuri.a $(PREFIX)/lib
	install -o 0 -g 0 -m 644 zuri-config.cmake $(PREFIX)/lib/cmake/zuri

.PHONY: uninstall
uninstall:
	rm -fi $(PREFIX)/include/zuri.h
	rm -fi $(PREFIX)/lib/libzuri.a
	rm -fir $(PREFIX)/lib/cmake/zuri
