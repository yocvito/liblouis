#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <liblouis.h>

#define BUF_MAX 4096
#define WBUF_MAX 4096*2

#define LANGUAGE	"en"


static widechar inputText[BUF_MAX] , outputText[BUF_MAX];
static int inputLen , outputLen;

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern int LLVMFuzzerInitialize(const int* argc, char*** argv);

int
LLVMFuzzerInitialize(const int *argc, char ***argv)
{

}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	inputLen = size;
	char *table_default = getenv("FUZZ_TABLE");
	if (table_default == NULL)
	{
		fprintf(stderr, "\n\n[Please set up FUZZ_TABLE env var before starting fuzzer]\n\n");
		return -1;
	}
	lou_backTranslateString(table_default, data, &inputLen, outputText, &outputLen, NULL, NULL, dotsIO);

	return 0;
}
