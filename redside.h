/*
 * settings.c
 */
// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.


typedef enum {
  kProtFS,
  kProtSFTP,
  kProtWebDAV,
  kProtDropbox,
  kProtBox,
  kProtS3,
  kProtFTP,
} Protocol;

typedef struct {
  char *service;
  char *path;
  char *user;
  char *password;       // What to do with this? KeyManager, encrypt? 
  char *protocol;
  Protocol protType;
} Backup;


typedef enum {
  kRoleMaster = 1,
  kRoleSlave,
  kRoleAsk,
} Role;


void settingsInit(void);
Backup *settingsIsync(void);
char **settingsDocs(void);
char **settingsIgnore(void);
Role settingsRole(void);

/*
 * util.c
 */

void progError(char *, ...);
char *mkName(char *);
char *mkName2(char *, char *);

/*
 * db.c
 */
typedef enum {
  STR_FREE,
  STR_RETAIN,
} StrAlloc;

typedef enum {
  kFlgNone           =    0,
  kFlgCryptSeen      =    1,
  kFlgActSetMode     =    2,
  kFlgActRemovePlain =    4,
  kFlgActRemoveCrypt =    8,
  kFlgActCrypt       = 0x10,
  kFlgActDecrypt     = 0x20,
} Flags;
typedef struct {
  long  mtime;
  char *name;
  short mode;
  long   plain_mtime;
  Flags  flags;
} DB;

void dbRead(void);
void dbWrite(void);
void setWrite(void);

long getNum(DB *dbp);
long name2Num(char *);
char *num2Name(long num);

void dbCheck(char *name);
StrAlloc dbAdd(char *name, long mtime, int mode);

void iterateDBInit(void);
DB *iterateDB(long *id);

/*
 * file checks
 */
void scanTree(char *, StrAlloc (*callback)(char *, long, int));
void docTrees(void);
void dataTree(void);

/*
 * actions.c
 */
int actEncrypt(DB *);
int actDecrypt(DB *);
int actRemovePlain(DB *);
int actRemoveCrypt(DB *);

/*
 * crypt.c
 */
void initFilepath(void);
int decryptWriter(void *, size_t);
int encryptWriter(void *, size_t);


int encryptFile(char *src, char *dst, char *name);
int decryptFile(char *src, char *dst);

/*
 * main.c
 */
int tflag;
