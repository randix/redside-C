// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "securesync.h"

static char *home = NULL;
static size_t homeLen;

void
progError(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(fmt, ap);
  fflush(stdout);
  va_end(ap);
  exit(1);
}

char *
mkName(char *n)
{
  char *name;

  if (home == NULL) {
    home = getenv("HOME");
    if (home == NULL)
      progError("HOME: cannot get environment value\n");
    homeLen = strlen(home);
  }

  name = malloc(homeLen + strlen(n) + 2);
  if (name == NULL)
    progError("cannot allocate memory\n");

  strcpy(name, home);
  strcat(name, "/");
  strcat(name, n);

  return(name);
}

char *
mkName2(char *n, char *n1)
{
  char *name;

  if (home == NULL) {
    home = getenv("HOME");
    if (home == NULL)
      progError("HOME: cannot get environment value\n");
    homeLen = strlen(home);
  }

  name = malloc(homeLen + strlen(n) + strlen(n1) + 3);
  if (name == NULL)
    progError("cannot allocate memory\n");

  strcpy(name, home);
  strcat(name, "/");
  strcat(name, n);
  strcat(name, "/");
  strcat(name, n1);

  return(name);
}

