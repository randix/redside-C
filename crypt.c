// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.


#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "securesync.h"
#include "symcrypt.h"

static FILE *fpIn;
static FILE *fpOut;


static unsigned char bufIn[32*1024];
static size_t bufInLen;


static int filepathSeen = 0;
static unsigned short nameLenNet = 0;
static unsigned short nameLenNetSeen = 0;
static unsigned short nameLen = 0;
static unsigned short nameSeen = 0;
static char filepath[1024];

static int
handleFilepath(char *name)
{
  printf("internal name: %s\n", name);

  return(0);
}

void
initFilepath(void)
{
  nameLenNet = 0;
  nameLenNetSeen = 0;
  nameLen = 0;
  nameSeen = 0;
  filepathSeen = 0;
}


int
decryptWriter(void *buf, size_t bufLen)
{
  size_t cc;

  if (!filepathSeen) {

    /* we could get the file name one byte at a time! */
    if (nameLenNetSeen < sizeof(nameLenNet)) {
      cc = bufLen >= (sizeof(nameLenNet) - nameLenNetSeen) ?
                     (sizeof(nameLenNet) - nameLenNetSeen) : bufLen;
      memcpy(&((uint8_t *)(&nameLenNet))[nameLenNetSeen], buf, cc);
      buf += cc;
      bufLen -= cc;
      nameLenNetSeen += cc;
      if (nameLenNetSeen == sizeof(nameLenNet)) {
        nameLen = ntohs(nameLenNet);
      }
    }
    if (nameSeen < nameLen) {
      cc = bufLen >= nameLen - nameSeen ?
                     nameLen - nameSeen : bufLen;
      memcpy(&filepath[nameSeen], buf, cc);
      buf += cc;
      bufLen -= cc;
      nameSeen += cc;
    }
    if (nameSeen == nameLen) {
      handleFilepath(filepath);
      filepathSeen = 1;
    }
  }
  if (bufLen == 0)
    return(0);

  if (!fpOut)
    progError("file not open?\n");
  cc = fwrite(buf, 1, bufLen, fpOut);
  if (cc != bufLen)
    printf("write error\n");

  return(0);
}

int
encryptWriter(void *buf, size_t bufLen)
{
  size_t cc;

  if (!fpOut)
    progError("file not open?\n");
  cc = fwrite(buf, 1, bufLen, fpOut);
  if (cc != bufLen)
    printf("write error\n");

  return(0);
}

static int
seeker(size_t seek)
{
  int rv;

  if (!fpOut)
    progError("file not open?\n");
  rv = fseek(fpOut, seek, SEEK_SET);
  if (rv < 0)
    printf("seek error\n");

  return(0);
}

int
encryptFile(char *src, char *dst, char *name)
{
    unsigned short nameLen;
    unsigned short nameLenNet;

    symCryptInit();

    fpIn = fopen(src, "r");
    if (fpIn == NULL) {
        printf("%s: cannot open\n", src);
        return -1;
    }
    fpOut = fopen(dst, "w+");

  encryptInit(&encryptWriter, &seeker);

  nameLen = strlen(name) + 1;
  nameLenNet = htons(nameLen);
  memcpy(bufIn, &nameLenNet, sizeof(nameLenNet));
  strcpy((char *)&bufIn[sizeof(nameLenNet)], name);
  bufInLen = sizeof(nameLenNet) + nameLen;

  encryptData(bufIn, bufInLen);

  while ((bufInLen = fread(bufIn, 1, sizeof(bufIn), fpIn)) > 0) {
    encryptData(bufIn, bufInLen);
  }

  encryptFinal();

  fclose(fpIn);
  fclose(fpOut);

  return(0);
}

int
decryptFile(char *src, char *dst)
{
  size_t cc;

  initFilepath();
  symCryptInit();

  fpIn = fopen(src, "r");
  if (!fpIn) {
    printf("%s: cannot open\n", src);
    return(-1);
  }
  fpOut = fopen(dst, "w+");
  if (!fpOut) {
    printf("%s: cannot open\n", dst);
    return(-1);
  }

  cc = fread(bufIn, 1, sizeof(Header), fpIn);
  if (cc != sizeof(Header)) {
    printf("header read error\n");
    return(-1);
  }
  decryptInit(&decryptWriter, bufIn);

  while ((bufInLen = fread(bufIn, 1, sizeof(bufIn), fpIn)) > 0) {
    decryptData(bufIn, bufInLen);
  }

  decryptFinal(kHmacCheck);

  fclose(fpIn);
  fclose(fpOut);

  return(0);
}
