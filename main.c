/* 
 * securesync
 */
// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.

#include <dirent.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "securesync.h"
#include "symcrypt.h"


/* XXX -m master -s slave ?? */

static int dflag = 0;
static int eflag = 0;
static char *file;
static char *path;

static int nflag = 0;
static int rflag = 0;
int tflag = 0;
/*
  tflag = 1 -- after DB read
  tflag = 2 -- after filesystem scan
  tflag = 4 -- after backup scan
  tflag = 8 -- after action scan
*/


typedef enum {
  kPlainMissing,
  kCryptMissing,
} Missing;

static Flags missingPlainAction = kFlgNone;
static Flags missingCryptAction = kFlgNone;

static void
usage(void)
{
  printf("\n"
         "securesync []\n"
         "\n"
         "   <default>                     update backups\n"
         "   -d [-f <file> | -p <path>]    decrypt file or folder\n"   // XXX
         "   -e [-f <file> | -p <path>]    encrypt file or folder\n"   // XXX
         "   -n                            no actions on local\n"      // XXX
         "   -r                            rebuild DB\n"               // XXX
         "   -t N                          debug level\n"
         "   -h                            this help\n"
         "   -?                            this help\n"
         "\n"
        );
  exit(1);
}

static void
parseOpts(int ac, char *av[])
{
  int ch;
  while ((ch = getopt(ac, av, "denrt:f:p:")) != -1) {
    switch (ch) {
      case 'd':
        dflag = 1;
        break;
      case 'e':
        eflag = 1;
        break;
      case 'f':
        file = malloc(strlen(optarg) + 1);
        strcpy(file, optarg);
        break;
      case 'p':
        path = malloc(strlen(optarg) + 1);
        strcpy(path, optarg);
        break;
      case 'n':
        nflag = 1;
        break;
      case 'r':
        rflag = 1;
        break;
      case 't':
        if (optarg[0] < '0' || optarg[0] > '9') {
          printf("%s: option requires a numeric argument -- %c\n", av[0], ch);
          usage();
        }
        tflag = atoi(optarg);
        break;
      case '?':
      case 'h':
      dafault:
        usage();
        break;
    }
  }
  if (tflag) {
    printf("dflag = %d\n", dflag);
    printf("eflag = %d\n", eflag);
    printf("file = %s\n", file);
    printf("path = %s\n", path);
    printf("nflag = %d\n", nflag);
    printf("rflag = %d\n", rflag);
    printf("tflag = %d\n", tflag);
  }
}

static Flags
ask(DB *dbp, Missing missing)
{
  char buf[8];
  Flags choice = kFlgNone;

  if (missing == kPlainMissing && (missingPlainAction != kFlgNone))
    return(missingPlainAction);

  if (missing == kCryptMissing && (missingCryptAction != kFlgNone))
    return(missingCryptAction);

  for (;;) {
    printf("\n%s: ", dbp->name);
    printf("%s\n\n", missing == kPlainMissing ? "backup is present, local is missing" :
                                                "local is present, backup is missing");
    printf("Options:\n");

    if (missing == kPlainMissing) {    // plain file missing
      printf("  [r] restore\n");
      printf("  [d] delete backup\n");
      readpassphrase("Choose: ", buf, sizeof(buf), RPP_ECHO_ON);
      if (buf[0] == 'r')
        choice = kFlgActDecrypt;
      if (buf[0] == 'd')
        choice = kFlgActRemoveCrypt;
      if (choice != kFlgNone)
        break;
  
    } else {          // crypt file missing
      printf("  [b] backup\n");
      printf("  [d] delete local\n");
      readpassphrase("Choose: ", buf, sizeof(buf), RPP_ECHO_ON);
      if (buf[0] == 'b')
        choice = kFlgActCrypt;
      if (buf[0] == 'd')
        choice = kFlgActRemovePlain;
      if (choice != kFlgNone)
        break;
    }
  }

  readpassphrase("Remember this choice for similer files? ",
                 buf, sizeof(buf), RPP_ECHO_ON);
  if (buf[0] == 'y') {
    if (missing == kPlainMissing)
      missingPlainAction = choice;
    else
      missingCryptAction = choice;
  }

  return(choice);
}

static void
dumpDB(char *type)
{
  DB *dbp;
  long id;

  iterateDBInit();
  while ((dbp = iterateDB(&id)) != NULL)
    printf("%s %2d %4ld %10ld   %10ld %04o %s\n", type, dbp->flags, id,
           dbp->plain_mtime, dbp->mtime, dbp->mode, dbp->name);
  printf("-----\n");
}

int
main(int ac, char *av[])
{
  DB *dbp;
  long id;
  Role role;
  int noUpdates = 0;

  parseOpts(ac, av);

  settingsInit();
  role = settingsRole();

  printf("read db...\n");
  dbRead();
  if (tflag & 1)
    dumpDB("db");

  printf("scan local...\n");
  docTrees();
  if (tflag & 2)
    dumpDB("fs");

  printf("scan backup...\n");
  dataTree();
  if (tflag & 4)
    dumpDB("bk");

  printf("check actions...\n");
  iterateDBInit();
  while ((dbp = iterateDB(&id)) != NULL) {

    if (dbp->flags & kFlgActRemoveCrypt)  // already scheduled for dup removal
      continue;

    if (dbp->plain_mtime && (dbp->flags & kFlgCryptSeen)) {
      /* both files exist */

      /* needs encryption */
      if (dbp->plain_mtime > dbp->mtime) {
        dbp->flags |= kFlgActCrypt;
        noUpdates ++;
        continue;
      }

      /* needs decryption */
      if (dbp->plain_mtime < dbp->mtime) {
        dbp->flags |= kFlgActDecrypt;
        noUpdates++;
        continue;
      }
    }

    /* plain file is missing */
    if (dbp->plain_mtime == 0 && dbp->mtime && dbp->flags & kFlgCryptSeen) {
      if (role == kRoleMaster)
        dbp->flags |= kFlgActRemoveCrypt;
      else if (role == kRoleSlave)
        dbp->flags |= kFlgActDecrypt;
      else
        dbp->flags |= ask(dbp, kPlainMissing);
      noUpdates++;
      continue;
    }

    /* crypt file is missing */
    if (dbp->plain_mtime && 
        (dbp->mtime == 0 || ((dbp->flags & kFlgCryptSeen) == 0))) {
      if (role == kRoleMaster)
        dbp->flags |= kFlgActCrypt;
      else if (role == kRoleSlave)
        dbp->flags |= kFlgActRemovePlain;
      else
        dbp->flags |= ask(dbp, kCryptMissing);
      noUpdates++;
      continue;
    }
  }

  if (tflag & 8)
    dumpDB("ac");

  if (noUpdates) {

    printf("\n");
    iterateDBInit();
    while ((dbp = iterateDB(&id)) != NULL) {
      if (dbp->flags == kFlgNone)
        continue;
      if (dbp->flags & kFlgActCrypt)
        printf("encrypt %s\n", dbp->name);
      if (dbp->flags & kFlgActDecrypt)
        printf("decrypt %s\n", dbp->name);
      if (dbp->flags & kFlgActRemoveCrypt)
        printf("remove backup for %s\n", dbp->name);
      if (dbp->flags & kFlgActRemovePlain)
        printf("remove %s\n", dbp->name);
    }
    printf("\n");

    printf("run %d actions...\n", noUpdates);

    symCryptInit();
    getPassword();

    iterateDBInit();
    while ((dbp = iterateDB(&id)) != NULL) {
      if (dbp->flags == kFlgNone)
        continue;
      if (dbp->flags & kFlgActCrypt)
        actEncrypt(dbp);
      if (dbp->flags & kFlgActDecrypt)
        actDecrypt(dbp);
      if (dbp->flags & kFlgActRemoveCrypt)
        actRemoveCrypt(dbp);
      if (dbp->flags & kFlgActRemovePlain)
        actRemovePlain(dbp);
    }
  }

  dbWrite();

  printf("done!\n");
  return(0);
}
