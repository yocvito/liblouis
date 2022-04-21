#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <liblouis.h>

#define BUF_MAX 4096

#define LANGUAGE	"en"

static int initialized = 0;

#define BOLDRED(x)	"\x1b[31m\x1b[1m" x "\x1b[0m"

static const char *table_default;

static void __attribute__((destructor))
free_ressources(void) {
	lou_free();
}

void
avoid_log(logLevels level, const char *msg) {
	(void) level;
	(void) msg;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!initialized)
	{
		lou_registerLogCallback(avoid_log);
		table_default = getenv("FUZZ_TABLE");
		initialized = 1;
	}

	int inputLen;
	int outputLen;
	char *mutable_data = strndup((char*)data, size);
	if (!mutable_data) 
	{
		perror("malloc");
		exit(1);
	}

	widechar inputText[size+1];
	widechar outputText[size*16+1];
	int ret = _lou_extParseChars(mutable_data, inputText);
	free(mutable_data);
	if (ret <= 0)
		return -1;

	inputLen = ret;
	outputLen = ret*16;
	if (table_default == NULL)
	{
		fprintf(stderr, "\n" BOLDRED("[Please set up FUZZ_TABLE env var before starting fuzzer]")"\nThis environment variable is supposed to contain the table you want to test with lou_translateString()\n\n");
		exit(0);
	}
	lou_translateString(table_default, inputText, &inputLen, outputText, &outputLen, NULL, NULL, ucBrl);

	return 0;
}