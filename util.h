#ifndef _AED_UTIL_H_
#define _AED_UTIL_H_

#include <openssl/evp.h>

#define FLAGS_SUPPORTED "dehp:s:"

struct flags
{
  int dflag;
  int eflag;
  char * password;
  /* 8-byte salt (no terminating null byte) */
  int sflag;
  unsigned char salt[PKCS5_SALT_LEN];
};

void
flags_init(struct flags *);
int
read_buffer(char *, size_t, int);
int
hex_to_byte(const char *, unsigned char *, size_t);

#endif /* _AED_UTIL_H_ */
