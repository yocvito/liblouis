CC=clang
OBJ=$(shell find ../.. -name "*.o" 2>/dev/null)
CFLAGS=-I../../liblouis/ -fsanitize=address,fuzzer

all: fuzz-pattern-compile fuzz-lou_translateString

.PHONY: clean loulib.a
loulib.a: $(OBJ)
	ar ruv $@ $^

fuzz-pattern-compile: fuzz_pattern_compile_expression.c loulib.a
	$(CC)  $(CFLAGS) $^ -o $@ 

fuzz-lou_translateString: fuzz_lou_translateString.c loulib.a
	$(CC)  $(CFLAGS) $^ -o $@ 

clean:
	rm -rf fuzz-*