#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <liblouis.h>

#define BUF_MAX 4096
#define WBUF_MAX 4096*2

#define LANGUAGE	getenv("LANG")


static widechar inputText[BUF_MAX] , output1Text[BUF_MAX];
 static int inputPos[BUF_MAX], outputPos[BUF_MAX];
 static formtype emp1[BUF_MAX];
static int inputLen , output1Len;

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern int LLVMFuzzerInitialize(const int* argc, char*** argv);

int
LLVMFuzzerInitialize(const int *argc, char ***argv)
{

}


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
	static const char table_default[256];
	sprintf(table_default,sizeof(table_default),"%s%s",getenv("LANG"),".ctb");
	lou_translate(table_default, data, size, output1Text, &output1Len, emp1, NULL,
				inputPos, outputPos, NULL, 0);

	return 0;
}
