#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "base64.h"

size_t
base64_encode(char **buf, const unsigned char *msg, size_t len)
{
	int i, j;
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

	size = 1 + (len / 4 ) * 3;
	size -= msg[len - 1] == '=' ? 1 : 0;
	size -= msg[len - 2] == '=' ? 1 : 0;

	printf("base64: %lu bytes\n", len);
	printf("clear : %lu bytes\n", size);

	return size;
}

int
main(int argc, char *argv[])
{
	int i;
	size_t len, n;
	char *buf = NULL, in[59];

	while ((n = read(0, in, 57)) > 0) {
		in[58] = 0;
		len = base64_encode(&buf, in, n);
		puts(buf);
		free(buf);
	}
	return 0;
}
