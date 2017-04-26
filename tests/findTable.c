/* liblouis Braille Translation and Back-Translation Library

Copyright (C) 2015 Bert Frees <bertfrees@gmail.com>

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved. This file is offered as-is,
without any warranty. */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "liblouis.h"
#include "internal.h"

int
main(int argc, char **argv)
{
  int success = 0;
  char * match;
  const char * tables[] = {"tests/tablesWithMetadata/foo","tests/tablesWithMetadata/bar",NULL};
  lou_setLogLevel(LOG_DEBUG);
  lou_indexTables(tables);
  match = lou_findTable("id:foo");
  success |= (!match || (strstr(match, "tablesWithMetadata/foo") == NULL));
  match = lou_findTable("language:en");
  success |= (!match || (strstr(match, "tablesWithMetadata/bar") == NULL));

  lou_free();
  return success;
}
