#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "base64.h"

#define BASE64_FOLD 76

int base64_index(const char *, char);

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
base64_index(const char *base64, char ch)
{
	uint8_t idx = 0;

	for (idx = 0; idx < 64; idx++)
		if (base64[idx] == ch)
			return idx;

	return -1;
}


size_t
base64_encode(char **buf, const unsigned char *msg, size_t len)
{
	size_t i, j;
	uint64_t b64;
	size_t size;

	/* calculate size needed for the base64 buffer */
	size = (len / 3) * 4 + (len % 3 ? 4 : 0);

	*buf = malloc(size);
	memset(*buf, 0, size);

	for (i = j = 0; i < len; i+=3) {
		/* concatenate 3 bytes into one 24 bits quantum, or 0 */
		b64 = 0;
		b64 |= (msg[i]<<16);
		b64 |= ((i+1 < len ? msg[i+1] : 0) << 8);
		b64 |= i+2 < len ? msg[i+2] : 0;

		/* extract 4 base64 values from it */
		(*buf)[j++] = base64_table[63 & (b64>>18)];
		(*buf)[j++] = base64_table[63 & (b64>>12)];
		(*buf)[j++] = i+1 < len ? base64_table[63 & (b64>>6)] : '=';
		(*buf)[j++] = i+2 < len ? base64_table[63 & b64] : '=';
	}

	return size;
}

size_t
base64_decode(char **buf, const unsigned char *msg, size_t len)
{
	uint64_t b64;
	size_t size, i, j;

	size = (len * 3) / 4;
	size -= msg[len - 1] == '=' ? 1 : 0;
	size -= msg[len - 2] == '=' ? 1 : 0;

	*buf = malloc(size);
	if (*buf == NULL)
		return 0;
	memset(*buf, 0, size);

	for (i = j = 0; i < len; i+=4) {
		b64 = 0;
		b64 |= (base64_index(base64_table, msg[i])<<18);
		b64 |= (base64_index(base64_table, msg[i+1])<<12);
		b64 |= i + 2 < len ? (base64_index(base64_table, msg[i+2])<<6) : 0;
		b64 |= i + 3 < len ? (base64_index(base64_table, msg[i+3])) : 0;

		(*buf)[j++] = 255 & (b64>>16);
		(*buf)[j++] = 255 & (b64>>8);
		(*buf)[j++] = 255 & (b64);
	}

	return size;
}

size_t
base64_fold(FILE *fp, char *base64, size_t len, size_t fold)
{
	size_t i;

	fold = fold > 0 ? fold : BASE64_FOLD;

	for (i = 0; i < len; i += BASE64_FOLD) {
		fwrite(base64+i, 1, i+BASE64_FOLD > len ? len - i : BASE64_FOLD, fp);
		fwrite("\n", 1, 1, fp);
	}

	return fold;
}
