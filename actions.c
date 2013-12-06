// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.


#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "redside.h"
#include "symcrypt.h"


static void
makedir(char *n)
{
  char *p;
  struct stat statbuf;
  int cont;
  int err;

  p = n;  // point to root '/...'
  
  while (*p) {
    p++;
    while (*p && *p != '/')
      p++;
    if (*p == '/') {
      *p = 0;
      cont = 1;

      if (stat(n, &statbuf) < 0) {
        err = mkdir(n, 0777);
        if (err < 0 && errno != EEXIST)
          progError("%s: cannot mkdir: %d\n", n, errno);
      }

    } else
      cont = 0;

    if (cont)
      *p = '/';
  }
}

int
actEncrypt(DB *dbp)
{
  Backup *bak;
  char *data;
  char *name;
  char *bname;
  char *sname;


// XXX
  bak = settingsIsync();
  data = bak[0].path;

  name = num2Name(getNum(dbp));
  bname = mkName2(data, name);
  makedir(bname);
  sname = mkName(dbp->name);

  printf("encrypt %s -> %s\n", dbp->name, name);

  encryptFile(sname, bname, dbp->name);

  free(bname);
  free(sname);

  dbp->mtime = dbp->plain_mtime;
  setWrite();

  return(0);
}

int
actDecrypt(DB *dbp)
{
  Backup *bak;
  char *data;
  char *name;
  char *bname;
  char *sname;
  struct timeval times[2];
  int err;


// XXX
  bak = settingsIsync();
  data = bak[0].path;

  name = num2Name(getNum(dbp));
  bname = mkName2(data, name);
  sname = mkName(dbp->name);
  makedir(sname);

  printf("decrypt %s -> %s\n", name, dbp->name);

  decryptFile(bname, sname);

  err = chmod(sname, dbp->mode);
  if (err < 0)
    printf("chmod: error %d\n", errno);

  times[0].tv_sec = dbp->mtime;
  times[0].tv_usec = 0;
  times[1].tv_sec = dbp->mtime;
  times[1].tv_usec = 0;
  err = utimes(sname, times);
  if (err < 0)
    printf("utimes: error %d\n", errno);

  free(bname);
  free(sname);

  return(0);
}

int
actRemoveCrypt(DB *dbp)
{
  Backup *bak;
  char *data;
  char *name;
  char *bname;
  int err;

  // XXX
  bak = settingsIsync();
  data = bak[0].path;

  name = num2Name(getNum(dbp));
  bname = mkName2(data, name);

  printf("remove backup: %s: %s\n", dbp->name, name);

  err = unlink(bname);
  if (err < 0)
    printf("unlink: error %d\n", errno);

  free(dbp->name);
  dbp->name = 0;
  setWrite();

  free(bname);

  return(0);
}

int
actRemovePlain(DB *dbp)
{
  Backup *bak;
  char *data;
  char *sname;
  int err;

  printf("remove local: %s\n", dbp->name);

// XXX
  bak = settingsIsync();
  data = bak[0].path;

  sname = mkName(dbp->name);

  err = unlink(sname);
  if (err < 0)
    printf("unlink: error %d\n", errno);

  free(dbp->name);
  dbp->name = 0;
  setWrite();

  free(sname);

  return(0);
}
