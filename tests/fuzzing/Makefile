CC=clang
OBJ=$(shell find ../.. -name "*.o" 2>/dev/null)
CFLAGS=-I../../liblouis/ -fsanitize=address,fuzzer

all: fuzz_pattern_compile_expression

.PHONY: clean loulib.a
loulib.a: $(OBJ)
	ar ruv $@ $^

fuzz: fuzz_pattern_compile_expression.c loulib.a
	$(CC)  $(CFLAGS) $^ -o $@ 

clean:
	rm -rf fuzz