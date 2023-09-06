.PHONY: test
test: urview.zig urlink.zig
	zig test urview.zig
	zig test urlink.zig

.PHONY: bench
bench: zig-out
	$?/bin/bench
	$?/bin/bench
	$?/bin/bench

urview-doc: urview.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

urlink-doc: urview.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

bench.asm: urview.zig urlink.zig bench.zig
	zig build-exe -O ReleaseFast -femit-asm=$@ -fno-emit-bin -fstrip bench.zig


zig-out: *.zig
	zig build


.PHONY: fuzz-params-console
fuzz-params-console: zig-out
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-params -O -g 0 -G 64 -- $?/bin/fuzz-params

.PHONY: fuzz-parse-console
fuzz-parse-console: zig-out
	afl-fuzz -i sample -o fuzz-parse -O -g 0 -G 64 -- $?/bin/fuzz-parse

.PHONY: fuzz-urn-console
fuzz-urn-console: zig-out
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-urn -O -g 0 -G 64 -- $?/bin/fuzz-urn


.PHONY: fmt
fmt: *.zig
	zig $@ $?

.PHONY: dist
dist: test fmt zig-out test-samples urview-doc urlink-doc

# TODO(pascaldekloe): Replace in build.zig pending
# <https://github.com/ziglang/zig/issues/16866>.
.PHONY: test-samples
test-samples: zig-out/bin/fuzz-parse
	./zig-out/bin/fuzz-parse < sample/bloat
	./zig-out/bin/fuzz-parse < sample/empty
	./zig-out/bin/fuzz-parse < sample/tricky
	./zig-out/bin/fuzz-parse < /dev/null
	./zig-out/bin/fuzz-parse < /dev/null
	./zig-out/bin/fuzz-parse < /dev/null
	./zig-out/bin/fuzz-parse < /dev/zero
	./zig-out/bin/fuzz-parse < /dev/zero
	./zig-out/bin/fuzz-parse < /dev/zero

.PHONY: clean
clean:
	rm -fr zig-cache zig-out
	rm -fr urview-doc urlink-doc
	rm -f bench.asm
