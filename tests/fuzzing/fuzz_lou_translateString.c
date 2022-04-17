#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "liblouis.h"

#define OUTBUFSIZ   4096

const char *tableList = "en-chess.ctb,en-ueb-math.ctb,en-us-comp8.ctb,en_CA.ctb,en-GB-g2.ctb,en-gb-comp8.ctb,en-in-g1.ctb,"
                        "en-ueb-g1.ctb,en-ueb-g2.ctb,en-us-comp6.ctb";
widechar outbuf[OUTBUFSIZ];

void __attribute__((constructor)) 
load_lou_tables()
{
    //printf("YO !\n");

}


void __attribute__((destructor)) 
unload_lou_tables()
{
    lou_free();
    //printf("BYE BYE !\n");
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int inlen = (Size % 2) ? Size-1 : Size;
    int outlen = OUTBUFSIZ;

    if (!lou_translateString(tableList, (const widechar *)Data, &inlen, outbuf, &outlen, NULL, NULL, 2))
        return 1;
    lou_free();
    return 0;
}