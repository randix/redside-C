// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.


#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <arpa/inet.h>
#include <readpassphrase.h>

#include "symcrypt.h"

static char saltsFile[] = ".securesyncSalts";
static char *saltsPath = 0;

/*
 * this is the header for each encrypted file
 */
static Header header = {
  kVersion1,
  kPassword,
  0,
};

enum {
  kPwdSaltLen = 4,
  kCryptoSaltLen = 8,
  kCryptoSaltMax = 16,
  kMinPasswordLen = 7,
  kMaxPasswordLen = 256,
};
static char password[kMaxPasswordLen] = {0,}; // aways secret

/*
 * This (both the struct and the hash+salt) is
 * stored in ~/.securesyncSalts in this order.
 */
static struct {
  uint8_t keySaltLen;
  uint8_t hmacSaltLen;
  uint8_t keySalt[kCryptoSaltMax];
  uint8_t hmacSalt[kCryptoSaltMax];
} securesyncSalts = {0,};
uint8_t passwordHash[CC_SHA256_BLOCK_BYTES+kPwdSaltLen] = {0,};


static uint8_t encKey[kCCKeySizeAES256];      // always secret
static uint8_t hmacKey[kCCKeySizeAES256];     // always secret

static CCHmacContext hmacContext;
static CCHmacContext hmacContextPlain;

static CCCryptorRef cryptorRef;

static uint8_t compressed[32*1024];
static size_t  compressedLen;
static uint8_t bufOut[32*1024];
static size_t  bufOutLen;

static z_stream strm;

static int (*writer)(void *, size_t);
static int (*seeker)(size_t);

void
testCalcIter(void)
{
  int iter;
  iter = CCCalibratePBKDF(kCCPBKDF2,
                          strlen(password),
                          securesyncSalts.keySaltLen,
                          kCCPRFHmacAlgSHA512,
                          kCCKeySizeAES256,
                          100);               // ms
  printf("iter=%d\n", iter);
}

static char *
getSaltsPath(void)
{
  char *home;

  if (!saltsPath) {
      home = getenv("HOME");
      saltsPath = malloc(strlen(home) + 2 + strlen(saltsFile));
      strcpy(saltsPath, home); strcat(saltsPath, "/"); strcat(saltsPath, saltsFile);
  }
  return(saltsPath);
}

static int
isZero(void *buf, unsigned size)
{
  int i;
  uint8_t *p = buf;
  int zero = 1;
  for (i=0; i < size; i++)
    if (p[i])
      zero = 0;
  return(zero);
}

static void
getSalt(uint8_t *salt, unsigned saltLen)
{
  int fd;
  int cnt;
  size_t cc;

    /* SecRandomCopyBytes on iOS */
  fd = open("/dev/random", O_RDONLY);
  if (fd < 0) {
      printf("random: cannot get salt\n");
      exit(1);
  }

  cnt = 0;
  while (cnt < saltLen) {
    cc = read(fd, &salt[cnt], saltLen - cnt);
    if (cc <= 0) {
      printf("cannot get salt\n");
      exit(1);
    }
    cnt += cc;
  }

  close(fd);
}

void
getPassword(void)
{
  char buf[kMaxPasswordLen+kPwdSaltLen];
  size_t bufLen;
  unsigned char hash[CC_SHA256_BLOCK_BYTES];
  uint8_t salt[kPwdSaltLen];
  int fd;
  off_t rv;

  if (!isZero(passwordHash, sizeof(passwordHash))) {
    if (isZero(password, sizeof(password))) {
      do {
        readpassphrase("password: ", password, sizeof(password), 0);

        strcpy(buf, password);
        bufLen = strlen(password);
        memcpy(&buf[bufLen], &passwordHash[CC_SHA256_BLOCK_BYTES], kPwdSaltLen);

        memset(hash, 0, sizeof(hash));
        CC_SHA512(buf, (int)bufLen+kPwdSaltLen, hash);

        if (memcmp(hash, passwordHash, CC_SHA256_BLOCK_BYTES)) {
          printf("incorrect password\n");
          sleep(1);
        }
      } while (memcmp(hash, passwordHash, CC_SHA256_BLOCK_BYTES));
    }
  } else {
    do {
      readpassphrase("password: ", password, sizeof(password), 0);
      if (strlen(password) < kMinPasswordLen) {
        printf("password is too short\n\n");
        continue;
      }
      readpassphrase("repeat password: ", buf, sizeof(buf), 0);
      if (strlen(password) < kMinPasswordLen || strcmp(password, buf))
        printf("passwords do not match\n\n");
    } while (strcmp(password, buf));

    getSalt(salt, kPwdSaltLen);
    bufLen = strlen(buf);
    memcpy(&buf[bufLen], salt, kPwdSaltLen);
    memset(passwordHash, 0, CC_SHA256_BLOCK_BYTES);
    CC_SHA512(buf, (int)bufLen+kPwdSaltLen, passwordHash);
    memcpy(&passwordHash[CC_SHA256_BLOCK_BYTES], salt, kPwdSaltLen);

    fd = open(getSaltsPath(), O_RDWR|O_CREAT, 0600);
    if (fd >= 0) {
      rv = lseek(fd, sizeof(securesyncSalts), SEEK_SET);
      rv = write(fd, passwordHash, CC_SHA256_BLOCK_BYTES+kPwdSaltLen);
      rv = close(fd);
    } else {
      printf("cannot save password hash\n");
    }
  }
}

int
symCryptInit(void)
{
  int fd;
  size_t rv;

  if (isZero(&securesyncSalts, sizeof(securesyncSalts))) {

    fd = open(getSaltsPath(), O_RDONLY, 0600);
    if (fd >= 0) {
      rv = read(fd, &securesyncSalts, sizeof(securesyncSalts));
      rv = read(fd, passwordHash, CC_SHA256_BLOCK_BYTES+kPwdSaltLen);
      rv = close(fd);
    }

    if (isZero(&securesyncSalts, sizeof(securesyncSalts))) {

      securesyncSalts.keySaltLen = kCryptoSaltLen;
      getSalt(securesyncSalts.keySalt, kCryptoSaltMax);
      securesyncSalts.hmacSaltLen = kCryptoSaltLen;
      getSalt(securesyncSalts.hmacSalt, kCryptoSaltMax);

      fd = open(getSaltsPath(), O_RDWR|O_CREAT, 0600);
      if (fd >= 0) {
        rv = write(fd, &securesyncSalts, sizeof(securesyncSalts));
        rv = close(fd);
      } else {
        printf("cannot save key salts\n");
      }
    }
  }

  return(0);
}

int
encryptInit(int (*writerFunc)(void *, size_t),
            int (*seekerFunc)(size_t))
{
  CCCryptorStatus status;
  int rv;

  writer = writerFunc;
  seeker = seekerFunc;

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  rv = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
  if (rv != Z_OK) {
    printf("zlib init error\n");
    return(-1);
  }

  getPassword();

  if (isZero(encKey, kCCKeySizeAES256) || isZero(hmacKey, kCCKeySizeAES256)) {

    header.keySaltLen = securesyncSalts.keySaltLen;
    memcpy(header.keySalt, securesyncSalts.keySalt, header.keySaltLen);

    /* AES KEY DERIVATION */
    rv = CCKeyDerivationPBKDF(kCCPBKDF2,
                              password, strlen(password),
                              header.keySalt, header.keySaltLen,
                              kCCPRFHmacAlgSHA512,
                              kIterations,
                              encKey, kCCKeySizeAES256);
    if (rv < 0) {
      printf("Key derivation: error: %d\n", rv);
      exit(1);
    }

    header.hmacSaltLen = securesyncSalts.hmacSaltLen;
    memcpy(header.hmacSalt, securesyncSalts.hmacSalt, header.hmacSaltLen);

    /* HMAC KEY DERIVATION */
    rv = CCKeyDerivationPBKDF(kCCPBKDF2,
                              password, strlen(password),
                              header.hmacSalt, header.hmacSaltLen,
                              kCCPRFHmacAlgSHA512,
                              kIterations,
                              hmacKey, kCCKeySizeAES256);
    if (rv < 0) {
      printf("HMAC Key derivation: error: %d\n", rv);
      exit(1);
    }
  }

  if (isZero(header.iv, sizeof(header.iv)))
    getSalt(header.iv, sizeof(header.iv));

  CCHmacInit(&hmacContext, kCCHmacAlgSHA512, hmacKey, kCCKeySizeAES256);
  CCHmacInit(&hmacContextPlain, kCCHmacAlgSHA512, hmacKey, kCCKeySizeAES256);

  status = CCCryptorCreate(kCCEncrypt,
                           kCCAlgorithmAES128,
                           kCCOptionPKCS7Padding,
                           encKey, kCCKeySizeAES256,
                           header.iv,
                           &cryptorRef);
  if (status != kCCSuccess) {
    printf("cryptor init error\n");
    return(-1);
  }

  seeker(sizeof(header));

  return(0);
}

int
encryptData(void *bufIn, size_t bufInLen)
{
  CCCryptorStatus status;
  int rv;

  CCHmacUpdate(&hmacContextPlain, bufIn, bufInLen);

  strm.next_in = bufIn;
  strm.avail_in = (uint)bufInLen;

  do {
    strm.next_out = compressed;
    strm.avail_out = sizeof(compressed);

    rv = deflate(&strm, Z_NO_FLUSH);
    if (rv != Z_OK && rv != Z_BUF_ERROR) {
      printf("zlib error %d\n", rv);
    }

    status = CCCryptorUpdate(cryptorRef,
                             compressed, sizeof(compressed) - strm.avail_out,
                             bufOut, sizeof(bufOut), &bufOutLen);
    if (status != kCCSuccess) {
      printf("cryptor update error\n");
      return(-1);
    }

    if (bufOutLen) {
      CCHmacUpdate(&hmacContext, bufOut, bufOutLen);
      writer(bufOut, bufOutLen);
    }
  } while (strm.avail_out == 0);

  return(0);
}

int
encryptFinal(void)
{
  CCCryptorStatus status;
  int rv;

  /* finish zlib */
  do {
    strm.next_out = compressed;
    strm.avail_out = sizeof(compressed);

    rv = deflate(&strm, Z_FINISH);
    if (rv != Z_OK && rv != Z_STREAM_END && rv != Z_BUF_ERROR) {
      printf("zlib error %d\n", rv);
    }

    status = CCCryptorUpdate(cryptorRef,
                             compressed, sizeof(compressed) - strm.avail_out,
                             bufOut, sizeof(bufOut), &bufOutLen);
    if (status != kCCSuccess) {
      printf("cryptor update error\n");
      return(-1);
    }

    if (bufOutLen) {
      CCHmacUpdate(&hmacContext, bufOut, bufOutLen);
      writer(bufOut, bufOutLen);
    }
  } while (strm.avail_out == 0);

  deflateEnd(&strm);

  status = CCCryptorFinal(cryptorRef,
                          bufOut, sizeof(bufOut), &bufOutLen);
  if (status != kCCSuccess) {
    printf("cryptor update error: %d\n", status);
  }

  if (bufOutLen) {
      CCHmacUpdate(&hmacContext, bufOut, bufOutLen);
      writer(bufOut, bufOutLen);
  }

  status = CCCryptorRelease(cryptorRef);
  if (status != kCCSuccess) {
    printf("cryptor release error\n");
  }

  CCHmacFinal(&hmacContext, &header.hmacDigest);
  CCHmacFinal(&hmacContextPlain, &header.hmacDigestPlain);

  seeker(0);
  writer(&header, sizeof(header));

  return(0);
}


int
decryptInit(int (*writerFunc)(void *, size_t), void *h)
{
  CCCryptorStatus status;
  int rv;

  writer = writerFunc;

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  rv = inflateInit(&strm);
  if (rv != Z_OK) {
    printf("zlib init error\n");
    return(-1);
  }

  getPassword();

  memcpy(&header, h, sizeof(header));

  if (isZero(encKey, kCCKeySizeAES256) ||
      memcmp(header.keySalt, securesyncSalts.keySalt, header.keySaltLen)) {

    securesyncSalts.keySaltLen = header.keySaltLen;
    memcpy(securesyncSalts.keySalt, header.keySalt, sizeof(header.keySalt));

    /* AES KEY DERIVATION */
    rv = CCKeyDerivationPBKDF(kCCPBKDF2,
                              password, strlen(password),
                              header.keySalt, header.keySaltLen,
                              kCCPRFHmacAlgSHA512,
                              kIterations,
                              encKey, kCCKeySizeAES256);
    if (rv < 0) {
      printf("Key derivation: error: %d\n", rv);
      exit(1);
    }
  }

  if (isZero(hmacKey, kCCKeySizeAES256) ||
      memcmp(header.hmacSalt, securesyncSalts.hmacSalt, sizeof(header.hmacSalt))) {

    securesyncSalts.hmacSaltLen = header.hmacSaltLen;
    memcpy(securesyncSalts.hmacSalt, header.hmacSalt, header.hmacSaltLen);

    /* HMAC KEY DERIVATION */
    rv = CCKeyDerivationPBKDF(kCCPBKDF2,
                              password, strlen(password),
                              header.hmacSalt, header.hmacSaltLen,
                              kCCPRFHmacAlgSHA512,
                              kIterations,
                              hmacKey, kCCKeySizeAES256);
    if (rv < 0) {
      printf("HMAC Key derivation: error: %d\n", rv);
      exit(1);
    }
  }

  CCHmacInit(&hmacContext, kCCHmacAlgSHA512, hmacKey, kCCKeySizeAES256);
  CCHmacInit(&hmacContextPlain, kCCHmacAlgSHA512, hmacKey, kCCKeySizeAES256);

  status = CCCryptorCreate(kCCDecrypt,
                           kCCAlgorithmAES128,
                           kCCOptionPKCS7Padding,
                           encKey, kCCKeySizeAES256,
                           header.iv,
                           &cryptorRef);
  if (status != kCCSuccess) {
    printf("cryptor init error\n");
    return(-1);
  }

  return(0);
}

int
decryptData(void *bufIn, size_t bufInLen)
{
  CCCryptorStatus status;
  int rv;

  CCHmacUpdate(&hmacContext, bufIn, bufInLen);

  status = CCCryptorUpdate(cryptorRef,
                           bufIn, bufInLen,
                           compressed, sizeof(compressed), &compressedLen);
  if (status != kCCSuccess) {
    printf("cryptor update error\n");
    return(-1);
  }

  if (compressedLen) {
    strm.next_in = compressed;
    strm.avail_in = (uint)compressedLen;

    do {
      strm.next_out = bufOut;
      strm.avail_out = sizeof(bufOut);

      rv = inflate(&strm, Z_NO_FLUSH);
      if (rv != Z_OK && rv != Z_STREAM_END && rv != Z_BUF_ERROR) {
         printf("zlib error %d\n", rv);
      }

      bufOutLen = sizeof(bufOut) - strm.avail_out;
      if (bufOutLen) {
        CCHmacUpdate(&hmacContextPlain, bufOut, bufOutLen);
        writer(bufOut, bufOutLen);
      }

    } while (strm.avail_out == 0);
  }

  return(0);
}

int
decryptFinal(HMACCheck hmacCheck)
{
  CCCryptorStatus status;
  int rv;
  uint8_t hmacDigest[CC_SHA512_DIGEST_LENGTH];

  status = CCCryptorFinal(cryptorRef,
                          compressed, sizeof(compressed), &compressedLen);
  if (status != kCCSuccess) {
    printf("cryptor update error\n");
    return(-1);
  }
  status = CCCryptorRelease(cryptorRef);
  if (status != kCCSuccess) {
    printf("cryptor release error\n");
  }

  if (compressedLen) {
    strm.next_in = compressed;
    strm.avail_in = (uint)compressedLen;

    do {
      strm.next_out = bufOut;
      strm.avail_out = sizeof(bufOut);

      rv = inflate(&strm, Z_FINISH);
      if (rv != Z_OK && rv != Z_STREAM_END && rv != Z_BUF_ERROR) {
         printf("zlib error\n");
      }

      bufOutLen = sizeof(bufOut) - strm.avail_out;
      if (bufOutLen) {
        CCHmacUpdate(&hmacContextPlain, bufOut, bufOutLen);
        writer(bufOut, bufOutLen);
      }

    } while (strm.avail_out == 0);
  }

  inflateEnd(&strm);

  if (hmacCheck == kHmacNoCheck)
    return(0);

  /* CHECK */
  CCHmacFinal(&hmacContext, &hmacDigest);
  if (memcmp(header.hmacDigest, hmacDigest, sizeof(hmacDigest)))
    printf("CRYPT CORRUPT\n");

  CCHmacFinal(&hmacContextPlain, &hmacDigest);
  if (memcmp(header.hmacDigestPlain, hmacDigest, sizeof(hmacDigest)))
    printf("PLAIN CORRUPT\n");

  return(0);
}
