// Copyright (c) 2013, Dowhaus Systems, LLC
// All rights reserved.


#include <zlib.h>
#include <CommonCrypto/CommonCrypto.h>


typedef enum {
  kVersion1 = 1,
  kVersion2,
} Version;

typedef enum {
  kPassword = 1,
  kSession,
} Method;

enum {
  kKeySaltLen =  8,
  kHMACSaltLen = 8,
  kIterations = 100000,
};

typedef enum {
  kHmacCheck,
  kHmacNoCheck,
} HMACCheck;

/*
 * File Format <Version 1>:
 */
typedef struct {
  uint16_t version;
  uint16_t method;
  uint16_t reserved;
  uint8_t  keySaltLen;
  uint8_t  hmacSaltLen;
  uint8_t  keySalt[kKeySaltLen];
  uint8_t  hmacSalt[kHMACSaltLen];
  uint8_t  iv[kCCBlockSizeAES128];
  uint8_t  hmacDigest[CC_SHA512_DIGEST_LENGTH];
  uint8_t  hmacDigestPlain[CC_SHA512_DIGEST_LENGTH];
} Header;
/*
 * followed by:
 *
 *  cipher:<len>filepath
 *  cipher data
 */


void testCalcIter(void);

void getPassword(void);

int symCryptInit(void);

int encryptInit(int (*writerFunc)(void *, size_t), int (*seekerFunc)(size_t));
int encryptData(void *bufIn, size_t bufInLen);
int encryptFinal(void);

int decryptInit(int (*writerFunc)(void *, size_t), void *header);
int decryptData(void *bufIn, size_t bufInLen);
int decryptFinal(HMACCheck);

