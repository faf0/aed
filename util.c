/*
 * Utility functions for sws.
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

/*
 * Initializes the flags and parameters to default values.
 */
void
flags_init(struct flags *flag)
{
  assert(flag != NULL);
  flag->dflag = 0;
  flag->eflag = 0;
  flag->sflag = 0;
  flag->password = NULL;
  bzero(flag->salt, sizeof(flag->salt));
}

/**
 * Fills buffer buffer and returns -1 on error. Otherwise, the number of bytes
 * read are returned.
 *
 * @param buf the buffer to fill
 * @param buf_len the length of the buffer
 * @param fd the file descriptor to read from
 * @return the number of bytes read or -1 if an error occurred.
 */
int
read_buffer(char *buf, size_t buf_len, int fd)
{
  int rval;
  int bytes_read;

  assert(buf != NULL);

  bytes_read = 0;

  do {
    if ((rval = read(fd, buf + bytes_read, buf_len - bytes_read)) < 0) {
      return -1;
    } else {
      bytes_read += rval;
    }
  } while ((rval != 0) && (bytes_read < buf_len));

  return bytes_read;
}

/**
 * Converts the given hexadecimal string to a byte buffer.
 *
 * @param hex a hexadecimal ASCII string without the 0x prefix.
 * @param dst the byte buffer to fill
 * @param dst_len the length of the byte buffer.
 * @return 0 on success and -1 on failure.
 */
int
hex_to_byte(const char * hex, unsigned char * dst, size_t dst_len)
{
  const char * hex_off;
  size_t dst_off;
  size_t hex_len;
  const char * hex_end;

  if ((hex == NULL) || (dst == NULL)) {
    return -1;
  }

  hex_len = strlen(hex);

  if ((hex_len % 2) != 0) {
    return -1;
  }

  hex_end = hex + hex_len;
  for (hex_off = hex, dst_off = 0; (hex_off < hex_end) && (dst_off < dst_len);
      hex_off += 2, dst_off++) {
    char first = *hex_off;
    char second = *(hex_off + 1);
    char buf[3];

    if (!isxdigit(first) || !isxdigit(second)) {
      return -1;
    }

    if (snprintf(buf, sizeof(buf), "%c%c", first, second) == 2) {
      dst[dst_off] = strtol(buf, NULL, 16);
    } else {
      return -1;
    }
  }

  return 0;
}
