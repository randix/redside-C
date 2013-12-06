// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <readpassphrase.h>
#include <unistd.h>
#include <CommonCrypto/CommonCrypto.h>

#include "redside.h"
#include "symcrypt.h"


static char settingsFile[] = ".redside";

enum {
  MAX_DOC     = 21,
  MAX_IGNORE  = 33,
  MAX_BACKUP  = 6,
};

static char *doc[MAX_DOC] = { NULL, };
static int docNxt = 0;

static char *ignore[MAX_IGNORE] = { NULL, };
static int ignoreNxt = 0;

static Backup backup[MAX_BACKUP] = { NULL, };
static int backupNxt = 0;

static Role role;


void
settingsInit(void)
{
  char *home;
  char *settings;
  FILE *fp;
  char buf[1024];
  char *p;
  char *q;
  Backup *bakp;

  home = getenv("HOME");
  settings = malloc(strlen(home) + strlen(settingsFile) + 2);
  strcpy(settings, home); strcat(settings, "/"); strcat(settings, settingsFile);
  fp = fopen(settings, "r");
  free(settings);
  if (fp == NULL) {
    fprintf(stderr, "Cannot open settings: $HOME/%s\n", settingsFile);
    exit(1);
  }

  while (fgets(buf, sizeof(buf), fp) != NULL) {

    p = strtok(buf, " \t\r\n");
    if (!p || *p == '#' || *p == 0)
      continue;
    q = strtok(NULL, " \t\r\n");
    if (!q || !*q)
      continue;

    if (!strcmp(p, "DOC_TREE")) {
      if (docNxt >= MAX_DOC-1) {
        printf("settings: too many DOC_TREEs\n");
        continue;
      }
      doc[docNxt] = malloc(strlen(q) + 1);
      strcpy(doc[docNxt++], q);

    } else if (!strcmp(p, "IGNORE")) {
      if (ignoreNxt >= MAX_IGNORE-1) {
        printf("settings: too many IGNOREs\n");
        continue;
      }
      ignore[ignoreNxt] = malloc(strlen(q) + 1);
      strcpy(ignore[ignoreNxt++], q);

    } else if (!strcmp(p, "BACKUP")) {
      if (backupNxt >= MAX_BACKUP-1) {
        printf("settings: too many BACKUPs\n");
        continue;
      }
      bakp = &backup[backupNxt++];

      bakp->service = malloc(strlen(q) + 1);
      strcpy(bakp->service, q);

      p = strtok(NULL, " \t\r\n");
      bakp->path = malloc(strlen(p) + 1);
      strcpy(bakp->path, p);

      p = strtok(NULL, " \t\r\n");
      bakp->user = malloc(strlen(p) + 1);
      strcpy(bakp->user, p);

      p = strtok(NULL, " \t\r\n");
      bakp->password = malloc(strlen(p) + 1);
      strcpy(bakp->password, p);

      p = strtok(NULL, " \t\r\n");
      bakp->protocol = malloc(strlen(p) + 1);
      strcpy(bakp->protocol, p);

      if (!strcmp(bakp->protocol, "fs"))
        bakp->protType = kProtFS;
      else if (!strcmp(bakp->protocol, "sftp"))
        bakp->protType = kProtSFTP;
      else if (!strcmp(bakp->protocol, "webdav"))
        bakp->protType = kProtWebDAV;
      else if (!strcmp(bakp->protocol, "dropbox"))
        bakp->protType = kProtDropbox;
      else if (!strcmp(bakp->protocol, "box"))
        bakp->protType = kProtBox;
      else if (!strcmp(bakp->protocol, "s3"))
        bakp->protType = kProtS3;
      else if (!strcmp(bakp->protocol, "ftp"))
        bakp->protType = kProtFTP;
      else
        printf("unknown protocol: %s\n", p);

    } else if (!strcmp(p, "ROLE")) {
      p = strtok(NULL, " \t\r\n");

      if (!strcmp(q, "master")) {
        role = kRoleMaster;
      } else if (!strcmp(q, "slave")) {
        role = kRoleSlave;
      } else if (!strcmp(q, "ask")) {
        role = kRoleAsk;
      } else
        printf("unknown role: %s\n", q);

    } else
      printf("unknown setting: %s\n", p);
  }

  fclose(fp);
}

Backup *
settingsIsync(void)
{
  return(backup);
}

char **
settingsDocs(void)
{
  return(doc);
}

char **
settingsIgnore(void)
{
  return(ignore);
}

Role
settingsRole(void)
{
  return(role);
}


//#define UNIT_TEST
#ifdef UNIT_TEST
/* UNIT Test */
int
main(int ac, char **av)
{
  int i;
  Backup *bak;
  Role role;
  char *dat;
  char **list;
  unsigned len;

  settingsInit();

  list = settingsDocs();
  for (i=0; list[i]; i++)
    printf("DOC_TREE %s\n", list[i]);

  list = settingsIgnore();
  for (i=0; list[i]; i++)
    printf("IGNORE %s\n", list[i]);

  bak = settingsIsync();
  for (i=0; bak[i].service; i++)
    printf("BACKUP %s %s %s%s %s %d\n",
                   bak[i].service,  bak[i].path,     bak[i].user,
                   bak[i].password, bak[i].protocol, bak[i].protType);

  role = settingsRole();
  printf("ROLE %d\n", role);

  
  symCryptInit();
  getPassword();

  return(0);
}
#endif /* UNIT_TEST */
