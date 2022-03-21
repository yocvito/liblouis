#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "../../liblouis/liblouis.h"
#define BUF_MAX 27720
static widechar inputText[BUF_MAX] , output1Text[BUF_MAX];
 static int inputPos[BUF_MAX], outputPos[BUF_MAX];
 static formtype emp1[BUF_MAX];
static int inputLen , output1Len;
 int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char new_file[256];
	sprintf(new_file, "/tmp/libfuzzer.uti");

	FILE *fp = fopen(new_file, "wb");
	if (!fp)
		return 0;
	fwrite(data, size, 1, fp);
	fclose(fp);

	char *table = "empty.ctb";
	//lou_compileString(table, "include /tmp/libfuzzer.uti");

	//lou_free();
	//std::__fs::filesystem::remove_all("/tmp/libfuzzer.uti");
	static const char table_default[] = "en-ueb-g2.ctb";
	lou_translate(table_default, data, size, output1Text, &output1Len, emp1, NULL,
				inputPos, outputPos, NULL, 0);

	return 0;
}
