.PHONY: test
test: urview.out urlink.out

urview.out: urview.zig
	zig test $? | tee $@

urlink.out: urlink.zig
	zig test $? | tee $@


.PHONY: bench
bench: zig-out
	$?/bin/bench
	$?/bin/bench
	$?/bin/bench


.PHONY: fmt
fmt: build.zig urview.zig urlink.zig fuzz-params.zig fuzz-parse.zig fuzz-urn.zig bench.zig
	zig $@ $?

urview-doc: urview.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

urlink-doc: urview.zig
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

bench.asm: urview.zig urlink.zig bench.zig
	zig build-exe -O ReleaseFast -femit-asm=$@ -fno-emit-bin -fstrip bench.zig


zig-out: build.zig urview.zig urlink.zig fuzz-params.zig fuzz-parse.zig fuzz-urn.zig bench.zig
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


.PHONY: dist
dist: test fmt zig-out test-samples urview-doc urlink-doc

# TODO(pascaldekloe): Replace in build.zig pending
# <https://github.com/ziglang/zig/issues/16866>.
.PHONY: test-samples
test-samples: zig-out/bin/fuzz-parse
	./zig-out/bin/fuzz-parse < sample/bloat
	./zig-out/bin/fuzz-parse < sample/empty
	./zig-out/bin/fuzz-parse < sample/tricky

.PHONY: clean
clean:
	rm -fr zig-cache zig-out
	rm -fr urview-doc urlink-doc
	rm -f *.out *.asm
