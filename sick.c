/* See LICENSE file for copyright and license details. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arg.h"
#include "base64.h"
#include "ed25519.h"

#define SIGBEGIN "\n-----BEGIN ED25519 SIGNATURE-----\n"
#define SIGEND "-----END ED25519 SIGNATURE-----\n"

enum {
	ACT_NONE,
	ACT_SIGN,
	ACT_CHCK
};

static void usage();
static int createkeypair(const char *);
static int sign(FILE *fp, FILE *key);

char *argv0;

static void
usage()
{
	fprintf(stderr, "usage: %s [-g ALIAS] [-f KEY] [-s [FILE..]]\n", argv0);
	exit(EXIT_FAILURE);
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
	if (fwrite(priv, 1, sizeof(pub), fp) < sizeof(pub)) {
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
	size_t len, siz = 0;
	char tmp[64], *base64;
	unsigned char sig[64], priv[64], *msg = NULL;

	while((len = fread(tmp, 1, 64, fp)) > 0) {
		siz += len;
		msg = realloc(msg, siz);
		memcpy(msg + siz - len, tmp, len);
	}

	fread(priv, 1, 64, key);
	ed25519_sign(sig, msg, siz, priv);

	len = base64_encode(&base64, sig, 64);
	fwrite(msg, 1, siz, stdout);
	fwrite(SIGBEGIN, 1, sizeof(SIGBEGIN), stdout);
	base64_fold(stdout, base64, len, 0);
	fwrite(SIGEND, 1, sizeof(SIGEND), stdout);

	return 0;
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

	return 0;
}
