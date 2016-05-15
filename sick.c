/* See LICENSE file for copyright and license details. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arg.h"
#include "base64.h"
#include "ed25519.h"

#define SIGBEGIN "-----BEGIN ED25519 SIGNATURE-----\n"
#define SIGEND   "-----END ED25519 SIGNATURE-----\n"

enum {
	ACT_NONE,
	ACT_SIGN,
	ACT_CHCK
};

static void usage();
static size_t bufferize(char **buf, FILE *fp);
static size_t extractmsg(unsigned char *msg[], char *buf);
static size_t extractsig(unsigned char *sig[], char *buf);
static int createkeypair(const char *);
static int sign(FILE *fp, FILE *key);
static int check(FILE *fp, FILE *key);

static int verbose = 0;
char *argv0;

static void
usage()
{
	fprintf(stderr, "usage: %s [-g ALIAS] [-f KEY] [-s [FILE..]]\n", argv0);
	exit(EXIT_FAILURE);
}

/*
 * read chunks of data from a stream into a buffer, and return the size of the buffer
 */
static size_t
bufferize(char **buf, FILE *fp)
{
	size_t n, len = 0;
	char chunk[MAX_INPUT], *tmp;

	while ((n = fread(chunk, 1, MAX_INPUT, fp)) > 0) {
		if ((tmp = realloc(*buf, len + n)) == NULL) {
			free(*buf);
			*buf = NULL;
			return 0;
		}

		*buf = tmp;
		memcpy((*buf) + len, chunk, n);
		len += n;
	}

	return len;
}

static size_t
extractmsg(unsigned char **msg, char *buf)
{
	size_t len = 0;
	char *sig;

	sig = strstr(buf, SIGBEGIN);

	if (sig == NULL)
		return -1;

	len = sig - buf;
	*msg = malloc(len);
	memcpy(*msg, buf, len);

	return len;
}

static size_t
extractsig(unsigned char **sig, char *buf)
{
	off_t i;
	size_t n, len = 0;
	char *begin, *end, *tmp;
	unsigned char base64[76];

	begin = strstr(buf, SIGBEGIN) + strlen(SIGBEGIN);
	end   = strstr(buf, SIGEND);

	if (!(begin && end)) {
		puts("Signature not found");
		return 0;
	}

	*sig = malloc(64);
	if (*sig == NULL)
		return 0;

	memset(*sig, 0, 64);

	/* base64 signature are wrapped at 76 chars */
	for (i = 0; begin+i < end; i+=77) {
		/* black magic pointer arithmetic there */
		n = begin+i+76 < end ? 76 : end - (begin + i);
		memset(base64, 0, 76);
		memcpy(base64, begin+i, n);

		n = base64_decode(&tmp, base64, n);
		memcpy((*sig) + len, tmp, n);
		len += n;
		free(tmp);
	}

	return len;
}

/*
 * Creates a set of ed25519 key pairs on disk.
 */
static int
createkeypair(const char *alias)
{
	size_t len = 0;
	FILE *fp = NULL;
	char fn[PATH_MAX];
	unsigned char seed[32], pub[32], priv[64];

	/*
	 * don't bother checking if `len > 0`. If the user wants to create
	 * files named ".key" and ".pub", that's OK.
	 */
	len = strnlen(alias, PATH_MAX);

	ed25519_create_seed(seed);
	ed25519_create_keypair(pub, priv, seed);

	/* write private key to "<alias>.key" */
	memset(fn, 0, PATH_MAX);
	memcpy(fn, alias, len);
	memcpy(fn+len, ".key", 4);
	if ((fp = fopen(fn, "w")) == NULL) {
		perror(fn);
		return -1;
	}
	if (fwrite(priv, 1, sizeof(priv), fp) < sizeof(priv)) {
		fclose(fp);
		perror(fn);
		return -1;
	}
	fclose(fp);

	/* write public key to "<alias>.pub" */
	memcpy(fn+len, ".pub", 4);
	if ((fp = fopen(fn, "w")) == NULL) {
		perror(fn);
		return -1;
	}
	if (fwrite(pub, 1, sizeof(pub), fp) < sizeof(pub)) {
		fclose(fp);
		perror(fn);
		return -1;
	}
	fclose(fp);

	return 0;
}

int
sign(FILE *fp, FILE *key)
{
	size_t len;
	char *base64, *buf = NULL;
	unsigned char sig[64], priv[64], *msg = NULL;

	if (!fread(priv, 1, 64, key))
		return -1;

	len = bufferize(&buf, fp);
	if (len == 0)
		return -1;

	msg = malloc(len);
	memcpy(msg, buf, len);
	free(buf);

	ed25519_sign(sig, msg, len, priv);

	/* write buffer to stdout .. */
	fwrite(msg, 1, len, stdout);
	free(msg);

	/* .. followed by the signature delimiter .. */
	fwrite(SIGBEGIN, 1, strlen(SIGBEGIN), stdout);

	/* .. then the base64 encoded signature .. */
	len = base64_encode(&base64, sig, 64);
	base64_fold(stdout, base64, len, 0);
	free(base64);

	/* .. and the final signature delimiter! */
	fwrite(SIGEND, 1, strlen(SIGEND), stdout);

	return 0;
}

static int
check(FILE *fp, FILE *key)
{
	int ret = 0;
	size_t len;
	char *buf = NULL;
	unsigned char *sig, *msg, pub[32];

	if (fread(pub, 1, 32, key) < 32)
		return -1;

	len = bufferize(&buf, fp);
	if (len == 0)
		return -1;

	if (extractsig(&sig, buf)) {
		len = extractmsg(&msg, buf);
		ret = ed25519_verify(sig, msg, len, pub);
		free(msg);
	}

	free(buf);
	free(sig);

	return !ret;
}

int
main(int argc, char *argv[])
{
	FILE *key = NULL, *fp = NULL;
	int action = ACT_NONE;

	ARGBEGIN{
	case 'f':
		key = fopen(EARGF(usage()), "r");
		break;
	case 'g':
		createkeypair(EARGF(usage()));
		break;
	case 's':
		action = ACT_SIGN;
		break;
	case 'v':
		verbose = 1;
		break;
	default:
		usage();
	}ARGEND;

	if (!argc) {
		fp = stdin;
		switch (action) {
		case ACT_SIGN:
			sign(fp, key);
			break;
		}
	}

	if (fp)
		fclose(fp);
	if (key)
		fclose(key);

	return 0;
}
