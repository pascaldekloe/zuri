.PHONY: test
test: zuri.out

zuri.out: zuri.zig
	zig test $? | tee $@


.PHONY: fmt
fmt: build.zig zuri.zig fuzz-parse.zig fuzz-uri.zig bench.zig
	zig $@ $?

doc: zuri.zig
	rm -fr doc
	zig build-lib -fno-emit-bin -femit-docs=$@ $?


zig-out: build.zig zuri.zig fuzz-parse.zig fuzz-uri.zig bench.zig
	zig build
	touch zig-out


zig-out/bin/fuzz-parse: zig-out
zig-out/bin/fuzz-uri: zig-out

.PHONY: fuzz-parse-console
fuzz-parse-console: zig-out/bin/fuzz-parse
	afl-fuzz -i sample -o fuzz-parse -O -- $?

.PHONY: fuzz-uri-console
fuzz-uri-console: zig-out/bin/fuzz-uri
	# samples not applicable yet it does not matter
	afl-fuzz -i sample -o fuzz-uri -O -- $?


zig-out/bin/bench: zig-out

bench.out: zig-out/bin/bench
	$? | tee $@


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
