#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <liblouis.h>

#define BUF_MAX 4096

#define LANGUAGE	"en"

static int initialized = 0;

#define BOLDRED(x)	"\x1b[31m\x1b[1m" x "\x1b[0m"

static widechar inputText[BUF_MAX];
static widechar outputText[BUF_MAX];
static int inputLen , outputLen;
static const char *table_default;

static void
__attribute__((destructor))
free_ressources(void)
{
	lou_free();
}

logcallback
avoid_log(logLevels level, const char *msg)
{
	(void) level;
	(void) msg;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!initialized)
	{
		lou_registerLogCallback(avoid_log);
		table_default = getenv("FUZZ_TABLE");
		initialized = 1;
	}

	if (!_lou_extParseChars(data, inputText))
		return -1;

	inputLen = size;
	if (table_default == NULL)
	{
		fprintf(stderr, "\n" BOLDRED("[Please set up FUZZ_TABLE env var before starting fuzzer]")"\n\n");
		exit(0);
	}
	lou_translateString(table_default, inputText, &inputLen, outputText, &outputLen, NULL, NULL, ucBrl);

	return 0;
}
