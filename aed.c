/*
 * Implementation of a an encryption/decryption utility using
 * AES in CBC mode using the SHA1 digest with 256-bit keys.
 * Supports password salting.
 * Reads data from stdin and writes results to stdout.
 */

#include <sys/types.h>
#include <sys/prctl.h>

#include <alloca.h>
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/unistd.h>
#include <bsd/readpassphrase.h>

#include <openssl/evp.h>

#include "util.h"

#define MAX_PASSWORD_LENGTH 256

static void
wait_for_stdin(void);
static int
read_password(char *, size_t, int);
static int
decrypt(unsigned char *);
static int
encrypt(unsigned char *, unsigned char *);
static void
usage(void);

/*
 * Waits for STDIN to become ready, if STDIN is not a TTY.
 */
static void
wait_for_stdin(void)
{
  fd_set rfds;
  int retval;

  if (isatty(fileno(stdin)))
    return;

  FD_ZERO(&rfds);
  FD_SET(fileno(stdin), &rfds);

  retval = select(1, &rfds, NULL, NULL, NULL);

  if (retval == -1)
    warnx("select failed waiting for stdin");
}

/**
 * Prompts for a password and reads the line entered.
 * The password is stored under buf and has a terminating NULL byte.
 *
 * @param buf the buffer where the password is to be stored
 * @param buf_len length in bytes of buf
 * @param verify 0 if the password should be read once. Otherwise, the password will
 *  be verified.
 * @return 0 on success and -1 otherwise.
 */
static int
read_password(char * buf, size_t buf_len, int verify)
{
  int runs;
  char * ver_buf;

  ver_buf = (char *) alloca(buf_len);

  if (buf_len < 1) {
    warnx("buffer too short to fit password");
    return -1;
  }

  runs = verify ? 2 : 1;

  do {
    if ((verify && (runs == 2)) || !verify) {
      if (readpassphrase("Password: ", buf, buf_len, RPP_REQUIRE_TTY) == NULL) {
        warnx("unable to read passphrase");
        return -1;
      }
    } else {
      if (readpassphrase("Verify: ", ver_buf, buf_len, RPP_REQUIRE_TTY)
          == NULL) {
        warnx("unable to read passphrase");
        return -1;
      }
      if (strcmp(buf, ver_buf) != 0) {
        warnx("password mismatch");
        return -1;
      }
    }
    runs--;
  } while (runs);

  return 0;
}

/**
 * Derives a key and initialization vector from the given password (required)
 * and salt (optional).
 *
 * @param flag structure containing the salt and the password
 * @param key the buffer where the encryption key is to be stored.
 *  Must be EVP_MAX_KEY_LENGTH bytes in size.
 * @param iv the buffer where the initialization vector is to be stored.
 *  Must be EVP_MAX_IV_LENGTH bytes in size.
 * @return 0 on success and -1 otherwise.
 */
static int
derive_key_iv(struct flags * flag, unsigned char * key, unsigned char * iv)
{
  int key_len;
  unsigned char * salt;

  salt = flag->sflag ? flag->salt : NULL;
  key_len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt,
      (unsigned char *) flag->password, (int) strlen(flag->password),
      PKCS5_DEFAULT_ITER, key, iv);

  return (key_len > 0) ? 0 : -1;
}

/**
 * Decrypts stdin and outputs the result to stdout.
 * The first EVP_MAX_IV_LENGTH bytes from stdin must contain the initialization
 * vector.
 *
 * @param key the key to use.
 * @return 0 on success and -1 otherwise.
 */
static int
decrypt(unsigned char * key)
{
  unsigned char inbuf[1024];
  unsigned char outbuf[1024];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  FILE *in;
  FILE *out;
  int inlen;
  int outlen;
  EVP_CIPHER_CTX ctx;
  int done;

  done = 0;

  in = stdin;
  out = stdout;
  inlen = fread(iv, 1, EVP_MAX_IV_LENGTH, in);

  EVP_CIPHER_CTX_init(&ctx);
  EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);

  if (ferror(in) || feof(in)) {
    warnx("cannot obtain IV");
    return -1;
  }

  do {
    inlen = fread(inbuf, 1, sizeof(inbuf), in);

    if (ferror(in)) {
      warnx("read from stdin failed");
      return -1;
    } else if (feof(in)) {
      done = 1;
    }

    if (!EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
      warnx("decrypt update failed");
      return -1;
    }

    if (fwrite(outbuf, 1, outlen, out) != outlen) {
      warnx("write to stdout failed");
      return -1;
    }
  } while (!done);

  if (!EVP_DecryptFinal_ex(&ctx, outbuf, &outlen)) {
    warnx("decrypt final failed");
    return -1;
  }

  EVP_CIPHER_CTX_cleanup(&ctx);

  if (fwrite(outbuf, 1, outlen, out) != outlen) {
    warnx("write to stdout failed");
    return -1;
  }
  if (fflush(out) == 0) {
    return 0;
  } else {
    return -1;
  }
}

/**
 * Encrypts stdin and outputs the result to stdout.
 * The first EVP_MAX_IV_LENGTH bytes from stdout will contain the initialization
 * vector.
 *
 * @param key the key to use.
 * @param iv the initialization vector to use.
 * @return 0 on success and -1 otherwise.
 */
static int
encrypt(unsigned char * key, unsigned char * iv)
{
  unsigned char inbuf[1024];
  unsigned char outbuf[1024];
  FILE *in;
  FILE *out;
  int outlen;
  EVP_CIPHER_CTX ctx;
  int done;

  done = 0;

  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);

  in = stdin;
  out = stdout;
  fwrite(iv, 1, EVP_MAX_IV_LENGTH, out);

  do {
    int inlen;

    inlen = fread(inbuf, 1, sizeof(inbuf), in);

    if (ferror(in)) {
      warnx("read from stdin failed");
      return -1;
    } else if (feof(in)) {
      done = 1;
    }

    if (!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
      warnx("encrypt update failed");
      return -1;
    }

    if (fwrite(outbuf, 1, outlen, out) != outlen) {
      warnx("write to stdout failed");
      return -1;
    }
  } while (!done);

  if (!EVP_EncryptFinal_ex(&ctx, outbuf, &outlen)) {
    warnx("encrypt final failed");
    return -1;
  }

  EVP_CIPHER_CTX_cleanup(&ctx);

  if (fwrite(outbuf, 1, outlen, out) != outlen) {
    warnx("write to stdout failed");
    return -1;
  }
  if (fflush(out) == 0) {
    return 0;
  } else {
    return -1;
  }
}

/*
 * Parses flags and encrypts or decrypts the data read from stdin.
 * Writes the resutls to stdout.
 */
#ifdef __linux__
int
main(int argc, char *argv[], char *envp[])
#else
int
main(int argc, char *argv[])
#endif
{
  char password[MAX_PASSWORD_LENGTH + 1];
  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  struct flags flag;
  int ch;
  int error;
  int hflag;
  int done;
  int i;
  int clear;

  /* change process title to remove password */
  #ifdef __linux__
  setproctitle_init(argc, argv, envp);
  #endif
  setproctitle("%s", argv[0]);
  prctl(PR_SET_NAME, argv[0], 0, 0, 0);

  bzero(key, sizeof(key));
  bzero(iv, sizeof(iv));
  bzero(password, sizeof(password));
  hflag = 0;
  error = 0;
  flags_init(&flag);
  setprogname((char *) argv[0]);

  while ((ch = getopt(argc, argv, FLAGS_SUPPORTED)) != -1) {
    switch (ch) {
    case 'd':
      flag.dflag = 1;
      break;
    case 'e':
      flag.eflag = 1;
      break;
    case 'h':
      hflag = 1;
      usage();
      break;
    case 'p':
      flag.password = optarg;
      break;
    case 's':
      if (strlen(optarg) != (2 * PKCS5_SALT_LEN)) {
        warnx("salt must consist of exactly 16 hexadecimal characters");
        error = 1;
      } else {
        int retval = hex_to_byte(optarg, flag.salt, sizeof(flag.salt));
        if (retval < 0) {
          warnx("failed to convert salt hexadecimal string to bytes");
        } else {
          flag.sflag = 1;
        }
      }
      break;
    default:
      usage();
      error = 1;
      break;
    }
  }

  done = hflag;

  /* check for error conditions */
  if (!done && !(flag.dflag ^ flag.eflag)) {
    warnx("either d or e flag must be set!");
    error = 1;
  }

  done = done || error;

  if (!done && (flag.password == NULL)) {
    int retval;

    wait_for_stdin();
    retval = read_password(password, sizeof(password), flag.eflag);
    flag.password = password;
    error = retval < 0;
  }

  done = done || error;

  /* derive the key and iv from the password */
  if (!done) {
    int retval;

    retval = derive_key_iv(&flag, key, iv);

    if (retval < 0) {
      warnx("key derivation failed");
      error = 1;
    }
  }

  done = done || error;

  /* clear password from argv, if it exists */
  for (clear = 0, i = 1; i < argc; i++) {
    if (clear) {
      int p;

      for (p = 0; p < strlen(argv[i]); p++) {
        argv[i][p] = '*';
      }
      break;
    }
    if (strcmp(argv[i], "-p") == 0) {
      clear = 1;
    }
  }

  /* decrypt or encrypt if arguments are fine */
  if (!done) {
    int retval;

    if (flag.dflag) {
      retval = decrypt(key);
    } else {
      retval = encrypt(key, iv);
    }

    error = retval < 0;
  }

  /* scrape the buffers containing secrets */
  bzero(password, sizeof(password));
  if (flag.password != NULL) {
    bzero(password, strlen(flag.password));
  }
  bzero(key, sizeof(key));

  return error ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Prints usage information and terminates this process.
 */
static void
usage(void)
{
  (void) fprintf(stderr, "usage: %s [-deh] [-p passphrase] [-s salt]\n",
      getprogname());
}

