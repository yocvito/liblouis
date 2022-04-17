#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "liblouis.h"

#define OUTBUFSIZ   4096

const char *tableList = "fr-bfu-g2.ctb";
widechar outbuf[OUTBUFSIZ];

void __attribute__((constructor)) 
load_lou_tables()
{
    //printf("YO !\n");

}


void __attribute__((destructor)) 
unload_lou_tables()
{
    //printf("BYE BYE !\n");
}

#include <fcntl.h>
#include <config.h>
#include <unistd.h>
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    int fd = open(".tmpfuzzer_lou_compileString.ini", O_RDONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }
    write(fd, Data, Size);
    close(fd);

    lou_compileString(tableList, "include .tmpfuzzer_lou_compileString.ini");
    lou_free();
    return 0;
}