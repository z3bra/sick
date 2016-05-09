#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "base64.h"

#define BASE64_FOLD 76

const char base64_table[] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M',
	'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
	'a','b','c','d','e','f','g','h','i','j','k','l','m',
	'n','o','p','q','r','s','t','u','v','w','x','y','z',
	'0','1','2','3','4','5','6','7','8','9','+','/'
};

size_t
base64_encode(char **buf, const unsigned char *msg, size_t len)
{
	size_t i, j;
	uint64_t b64;
	size_t size;

	/* calculate size needed for the base64 buffer */
	size = 1 + (len / 3) * 4 + (len % 3 ? 4 : 0);

	*buf = malloc(size);
	memset(*buf, 0, size);

	for (i = j = 0; i < len; i+=3) {
		/* concatenate 3 bytes into one 24 bits quantum, or 0 */
		b64 = 0 | (msg[i]<<16);
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
	size_t size;

	size = 1 + (len * 3) / 4;
	size -= msg[len - 1] == '=' ? 1 : 0;
	size -= msg[len - 2] == '=' ? 1 : 0;

	*buf = malloc(size);
	memset(*buf, 0, size);

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
