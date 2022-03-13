#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "internal.h"
#include <string.h>

#define TMP_FILE	"/tmp/libfuzzer-liblouis"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint16_t))
        return 1;

	int fd = open(TMP_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (fd < 0)
	{
		perror("open");
		return 1;
	}
	if (write (fd, Data, Size) != Size)
	{
		perror("write");
		return 1;
	}
	close(fd);


	//lou_compileString();

	unlink(TMP_FILE);
  return 0;
}
