// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.

/*
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "redside.h"


static StrAlloc
docFile(char *n, long mtime, int mode)
{
  return(dbAdd(n, mtime, mode));
}

static size_t bakPathLen = 0;
static StrAlloc
dataFile(char *n, long mtime, int mode)
{
  char *p;

  p = n + bakPathLen;

  dbCheck(p);
  return(STR_FREE);
}


static void
traverse(DIR *dirp, char *path, StrAlloc (*callback)(char *, long, int))
{
  char *relName;
  char *fulName;

  struct dirent *entry;
  struct stat st;

  DIR *ndirp;
  StrAlloc rv;

  int i;
  int match;
  char **ignore;

  ignore = settingsIgnore();
  while ((entry = readdir(dirp)) != NULL) {

    if (!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name))
      continue;

    match = 0;
    for (i=0; ignore[i]; i++) {
      if (!strcmp(ignore[i], entry->d_name)) {
        match = 1;
        break;
      }
    }
    if (match)
      continue;

    /* relName */
    relName = malloc(strlen(path) + strlen(entry->d_name) + 2);
    *relName = 0;
    if (strlen(path) > 0) {
      strcat(relName, path); strcat(relName, "/");
    }
    strcat(relName, entry->d_name);

    /* fulName */
    fulName = mkName(relName);

    stat(fulName, &st);

    if ((st.st_mode & S_IFWHT) == S_IFREG) {
      rv = (*callback)(relName, st.st_mtime, st.st_mode & 0777);
    }
    
    if ((st.st_mode & S_IFWHT) == S_IFDIR) {
      ndirp = opendir(fulName);
      traverse(ndirp, relName, callback);
      closedir(ndirp);
    }

    free(fulName);
    if (rv == STR_FREE)
      free(relName);
  }
}

void
scanTree(char *name, StrAlloc (*callback)(char *, long, int))
{
  char *dir;
  DIR *dirp;
  struct stat st;
  StrAlloc rv;

  dir = mkName(name);
  stat(dir, &st);
  if (st.st_mode & S_IFDIR) {
    dirp = opendir(dir);
    if (dirp) {
      traverse(dirp, name, callback);
      closedir(dirp);
    }
  } else {
    /* the path is a file, no traversing! */
    char *relName;
    relName = malloc(strlen(name) + 1);
    strcpy(relName, name);
    rv = (*callback)(relName, st.st_mtime, st.st_mode & 0777);
    if (rv == STR_FREE)
      free(relName);
  }
  free(dir);
}

void
docTrees(void)
{
  int i;
  char **doc;

  doc = settingsDocs();

  for (i=0; doc[i]; i++)
    scanTree(doc[i], &docFile);
}

void
dataTree(void)
{
  Backup *bak;
  char *data;

// XXX  lots of work here
  bak = settingsRedSide();
  data = bak[0].path;

  bakPathLen = strlen(data) + 1;
  scanTree(data, &dataFile);
}
