// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.

/*
 */

#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "redside.h"


enum {
  DB_SIZE_INCR = 1024,
};

static DB *db = NULL;
static long dbAlloc = 0;
static long dbFill = 0;
static long dbIter = 0;

static int rewriteMapfile = 0;


static void
alloc_chunk(void)
{
  long dbAllocOld;

  dbAllocOld = dbAlloc;
  dbAlloc += DB_SIZE_INCR;
  if (db)
    db = realloc(db, dbAlloc * sizeof(DB));
  else
    db = malloc(dbAlloc * sizeof(DB));
  if (db == NULL)
    progError("cannot alloc memory: db\n");

  memset(&db[dbAllocOld], 0, DB_SIZE_INCR * sizeof(DB));
}

char *
num2Name(long n)
{
  char nbuf[32];
  char sbuf[64];
  int nbufi = 0;
  int sbufi = 0;
  char *name;

  if (n == 0)
    nbuf[nbufi++] = 0;
  while (n) {
    nbuf[nbufi++] = n % 10;
    n /= 10;
  }

  while (nbufi-- > 1) {
    sbuf[sbufi++] = nbuf[nbufi] + 'a';
    sbuf[sbufi++] = '/';
  }

  sbuf[sbufi++] = nbuf[nbufi] + 'k';
  sbuf[sbufi] = 0;

  name = malloc(strlen(sbuf) + 1);
  strcpy(name, sbuf);

  return(name);
}

long
getNum(DB *dbp)
{
  return(dbp - db);
}

long
name2Num(char *n)
{
  int num = 0;

  /*
   * [a-j] are directories
   * [k-t] are files
   * [u..] are files not part of the scheme
   */
  while (*n) {

    if (*n > 't')
      return(-1);

    num += *n - 'a';
    if (*n >= ('a' + 10))
      num -= 10;
    n++;
    if (!*n)
      break;
    if (*n == '/')
      n++;
    num *= 10;
  }
  return(num);
}

void
setWrite(void)
{
  rewriteMapfile = 1;
}


/*
 * called for each real backup file
 */
void
dbCheck(char *name)
{
  long i;

  i = name2Num(name);
  if (i < 0) {
    return;
  }

  while (i >= dbAlloc)
      alloc_chunk();
  if (i >= dbFill)
    dbFill = i+1;

  db[i].flags |= kFlgCryptSeen;

  if (db[i].name == NULL) {
    printf("%ld %s: unknown backup, schedule removal\n", i, name);
    db[i].flags |= kFlgActRemoveCrypt;
  }
}

/*
 * called for each file system file
 */
StrAlloc
dbAdd(char *name, long mtime, int mode)
{
  DB *dbp = NULL;
  int i;

  for (i=0; i < dbFill; i++) {
    if (db[i].name && !strcmp(db[i].name, name)) {
      if (!dbp) {
        dbp = &db[i];
      } else {
        /* duplicate */
        printf("%s: duplicate backup, schedule removal\n", db[i].name);
        db[i].flags |= kFlgActRemoveCrypt;
      }
    }
  }

  if (dbp) {
    dbp->plain_mtime = mtime;
    dbp->mode = mode;
    return(STR_FREE);
  }

  for (i=0; i < dbFill; i++)
    if (!db[i].name)
      break;
  if (i < dbFill) {
    setWrite();
    dbp = &db[i];
    goto fill;
  }

  if (dbFill >= dbAlloc)
    alloc_chunk();

  dbp = &db[dbFill++];

fill:
  dbp->name = name;
  dbp->plain_mtime = mtime;
  dbp->mode = mode;
  return(STR_RETAIN);
}

/*
 * this reads the info file and builds up the internal
 * db[], if the file is present
 */
static int
dbReadFile(char *fn)
{
  long id;
  char *p, *q;
  DB *dbp;
  FILE *fp;
  char fname[2048];

  //printf("db: %s\n", fn);
  fp = fopen(fn, "r");
  if (fp == NULL) {
    fprintf(stderr, "%s: cannot read\n", fn);
    return(-1);
  }

// decrypt as reading XXX
  while (fgets(fname, sizeof(fname), fp) != NULL) {

    /* id timestamp mode name */
    id = strtol(fname, &p, 10);

    while (id >= dbAlloc)
      alloc_chunk();

    if (id > dbFill)
      dbFill = id+1;

    dbp = &db[id];

    dbp->mtime = strtol(p, &p, 10);
    dbp->mode = strtol(p, &p, 8);

    p++;
    q = p;                          /* name */
    while (*p && *p != '\r' && *p != '\n') p++;
    *p++ = 0;
    dbp->name = malloc(strlen(q) + 1);
    strcpy(dbp->name, q);
    if (tflag & 1)
      printf("-- %2d %4ld %10ld   %10ld %04o %s\n", dbp->flags, id,
             dbp->plain_mtime, dbp->mtime, dbp->mode, dbp->name);
  }
  if (ferror(fp)) {
    printf("read error\n");
    perror(fn);
  }

  fclose(fp);

  return(0);
}

void
dbRead(void)
{
  Backup *bak;
  char *data;
  char *n;

  // XXX
  bak = settingsIsync();
  data = bak[0].path;

  n = mkName2(data, "u");

  if (dbReadFile(n) < 0) {
    setWrite();
    free(n);
    n = mkName2(data, "v");
    dbReadFile(n);
  }
  free(n);
}


static void
dbWriteFile(char *n)
{
  int i;
  FILE *fp;

  fp = fopen(n, "w+");
  if (fp == NULL) {
    fprintf(stderr, "%s: cannot write\n", n);
    perror(n);
    return;
  }

// encrypt as writing XXX
  for (i=0; i < dbFill; i++)
    if (db[i].name && (db[i].flags || db[i].mtime || db[i].plain_mtime))
      fprintf(fp, "%d %ld 0%o %s\n", i, db[i].mtime, db[i].mode, db[i].name);

  fclose(fp);
}

void
dbWrite(void)
{
  Backup *bak;
  char *data;
  char *n;
  //struct timeval times[2];

  if (!rewriteMapfile)
    return;

  printf("write db\n");
  bak = settingsIsync();
  data = bak[0].path;

  n = mkName2(data, "u");
  dbWriteFile(n);
  free(n);

  n = mkName2(data, "v");
  dbWriteFile(n);
  free(n);
}


void
iterateDBInit(void)
{
  dbIter = 0;
}

DB *
iterateDB(long *id)
{
  if (dbIter >= dbFill) {
    return(NULL);
  }
  
  *id = dbIter;
  return(&db[dbIter++]);
}
