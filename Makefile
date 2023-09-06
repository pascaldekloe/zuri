.PHONY: test
test: Urlink.zig Urname.zig Urview.zig
	zig test Urlink.zig
	zig test Urname.zig
	zig test Urview.zig

.PHONY: bench
bench: zig-out
	$?/bin/bench
	$?/bin/bench
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


.PHONY: fuzz-parse-console
fuzz-parse-console: zig-out
	afl-fuzz -i sample -o fuzz-parse -O -g 0 -G 64 -- $?/bin/fuzz-parse

.PHONY: fuzz-url-console
fuzz-url-console: zig-out
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-url -O -g 0 -G 512 -- $?/bin/fuzz-url

.PHONY: fuzz-urn-console
fuzz-urn-console: zig-out
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-urn -O -g 0 -G 64 -- $?/bin/fuzz-urn


.PHONY: fmt
fmt: *.zig
	zig $@ $?

.PHONY: dist
dist: test fmt zig-out test-samples doc

# TODO(pascaldekloe): Replace in build.zig pending
# <https://github.com/ziglang/zig/issues/16866>.
.PHONY: test-samples
test-samples: zig-out
	./zig-out/bin/fuzz-parse < sample/bloat
	./zig-out/bin/fuzz-parse < sample/empty
	./zig-out/bin/fuzz-parse < sample/tricky
	./zig-out/bin/fuzz-parse < /dev/null
	./zig-out/bin/fuzz-url < /dev/null
	./zig-out/bin/fuzz-urn < /dev/null
	./zig-out/bin/fuzz-parse < /dev/zero
	./zig-out/bin/fuzz-url < /dev/zero
	./zig-out/bin/fuzz-urn < /dev/zero

.PHONY: clean
clean:
	rm -fr zig-cache zig-out
	rm -fr Urlink-doc Urname-doc Urview-doc
	rm -f bench.asm
