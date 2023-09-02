.PHONY: test
test: zuri.out

.PHONY: bench
bench: zig-out
	$?/bin/bench
	$?/bin/bench
	$?/bin/bench

zuri.out: zuri.zig
	zig test $? | tee $@


.PHONY: fmt
fmt: build.zig zuri.zig fuzz-params.zig fuzz-parse.zig fuzz-urn.zig bench.zig
	zig $@ $?

doc: zuri.zig
	rm -fr doc
	zig build-lib -fno-emit-bin -femit-docs=$@ $?

bench.asm: zuri.zig bench.zig
	zig build-exe -O ReleaseFast -femit-asm=$@ -fno-emit-bin -fstrip bench.zig


zig-out: build.zig zuri.zig fuzz-params.zig fuzz-parse.zig fuzz-urn.zig bench.zig
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
dist: test fmt doc zig-out test-samples

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
	rm -fr doc
	rm -f *.out *.asm
