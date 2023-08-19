.PHONY: test
test: zuri.out

zuri.out: zuri.zig
	zig test $? | tee $@


.PHONY: fmt
fmt: build.zig zuri.zig fuzz-parse.zig
	zig $@ $?

doc: zuri.zig
	rm -fr doc
	zig build-lib -fno-emit-bin -femit-docs=$@ $?


zig-out: build.zig zuri.zig fuzz-parse.zig
	zig build
	touch zig-out


zig-out/bin/fuzz-parse: zig-out

.PHONY: fuzz-parse-console
fuzz-parse-console: zig-out/bin/fuzz-parse
	afl-fuzz -i sample -o fuzz -O -- $?


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
	rm -f *.out