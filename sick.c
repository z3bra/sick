/* See LICENSE file for copyright and license details. */
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "arg.h"
#include "base64.h"
#include "ed25519.h"

#define SIGBEGIN "-----BEGIN ED25519 SIGNATURE-----\n"
#define SIGEND   "-----END ED25519 SIGNATURE-----\n"

enum {
	ACT_NONE,
	ACT_SIGN,
	ACT_CHCK,
	ACT_TRIM
};

enum {
	ERR_NOKEY  = 1,
	ERR_NOSIG  = 2,
	ERR_NOMSG  = 3,
	ERR_NORING = 4
};

static void usage();
static char *memstr(const void *h0, size_t k, const char *n0, size_t l);
static size_t bufferize(char **buf, FILE *fp);
static size_t extractmsg(unsigned char *msg[], char *buf, size_t len);
static size_t extractsig(unsigned char *sig[], char *buf, size_t len);
static int createkeypair(const char *);
static int check_keyring(unsigned char *sig, unsigned char *msg, size_t len);
static int sign(FILE *fp, FILE *key);
static int check(FILE *fp, FILE *key);
static int trimsig(FILE *fp);

char *argv0;
static int verbose = 0;

static void
usage()
{
	fprintf(stderr, "usage: %s [-stv] [-g ALIAS] [-f KEY] [FILE]\n",
			argv0);
	exit(EXIT_FAILURE);
}

/*
 * Find a string within a memory chunk, stupid style!
 */
char *
memstr(const void *h0, size_t k, const char *n0, size_t l)
{
	size_t i;
        const char *h = h0;

        /* Return immediately on empty needle */
        if (!l) return (char *)h;

        /* Return immediately when needle is longer than haystack */
        if (k<l) return 0;

	for (i=0; i<(k-l); i++) {
		if (memcmp(h+i, n0, l) == 0)
			return (char *)(h+i);
	}
	return NULL;
}

/*
 * read chunks of data from a stream into a buffer, and return the size of the
 * buffer
 */
static size_t
bufferize(char **buf, FILE *fp)
{
	size_t n, len = 0;
	char chunk[MAX_INPUT], *tmp;

	/*
	 * For each chunk read, reallocate the buffer size to fit the newly
	 * read data, and copy it over
	 */
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

/*
 * Copy the full content of the buffer, minus the signature to the given
 * pointer
 */
static size_t
extractmsg(unsigned char **msg, char *buf, size_t buflen)
{
	size_t len = 0;
	char *sig;

	/* signature start is identified by SIGBEGIN */
	sig = memstr(buf, len, SIGBEGIN, strlen(SIGBEGIN));

	/* if signature is not found, return the whole buffer */
	if (sig == NULL) {
		len = buflen;
	} else {
		len = sig - buf;
	}

	*msg = malloc(len);
	memcpy(*msg, buf, len);

	return len;
}

/*
 * Copy the signature at the end of the buffer to the given pointer
 */
static size_t
extractsig(unsigned char **sig, char *buf, size_t len)
{
	off_t i;
	size_t n, siglen = 0;
	char *begin, *end, *tmp;
	unsigned char base64[76];

	/* search start and end strings for the signatures */
	begin = memstr(buf, len, SIGBEGIN, strlen(SIGBEGIN)) + strlen(SIGBEGIN);
	end   = memstr(buf, len, SIGEND, strlen(SIGEND));
	if (!(begin && end))
		return 0;

	/* ed25519 signatures are 64 bytes longs */
	*sig = malloc(64);
	if (*sig == NULL)
		return 0;

	memset(*sig, 0, 64);

	/*
	 * base64 signature are wrapped at 76 chars.
	 * 76 being a multiple of 4, it means we can decode the signature in
	 * chunks of 76 bytes, and concatenate them together to get the
	 * original data.
	 */
	for (i = 0; begin+i < end; i+=77) {
		/*
		 * black magic pointer arithmetic there..
		 * if we reached the "end" pointer, it means we're at the end
		 * of the signature.
		 * The line length is either 76 bytes long, or less (for the
		 * last line)
		 */
		n = begin+i+76 < end ? 76 : end - (begin + i);
		memset(base64, 0, 76);
		memcpy(base64, begin+i, n);

		n = base64_decode(&tmp, base64, n);
		memcpy((*sig) + siglen, tmp, n);
		siglen += n;
		free(tmp);
	}

	return siglen;
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
	if (verbose)
		fprintf(stderr, "Creating private key %s\n", fn);
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
	if (verbose)
		fprintf(stderr, "Creating public key %s\n", fn);
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

/*
 * Buffer a data stream, sign it, and write the buffer + base64 encoded
 * signature to stdout
 */
int
sign(FILE *fp, FILE *key)
{
	size_t len;
	char *base64, *buf = NULL;
	unsigned char sig[64], priv[64], *msg = NULL;

	if (key == NULL)
		return ERR_NOKEY;

	if (!fread(priv, 1, 64, key))
		return ERR_NOKEY;

	len = bufferize(&buf, fp);
	if (len == 0)
		return ERR_NOMSG;

	msg = malloc(len);
	memcpy(msg, buf, len);
	free(buf);

	if (verbose)
		fprintf(stderr, "Signing stream (%lu bytes)\n", len);

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

/*
 * Check a buffer against all files in the $KEYRING directory set in the
 * environment.
 */
static int
check_keyring(unsigned char *sig, unsigned char *msg, size_t len)
{
	int ret = 0;
	size_t n = 0;
	DIR *dirp = NULL;
	FILE *key = NULL;
	struct dirent *dt = NULL;
	char *keyring = NULL, path[PATH_MAX];
	unsigned char pub[32];

	/* get the keyring from the environment */
	keyring = getenv("KEYRING");
	if (keyring == NULL) {
		if (verbose)
			fprintf(stderr, "KEYRING not set\n");
		return ERR_NORING;
	}

	dirp = opendir(keyring);
	if (dirp == NULL) {
		perror(keyring);
		return ERR_NORING;
	}

	/* loop through all entries in the $KEYRING directory */
        while ((dt = readdir(dirp)) != NULL) {
		/* ignore entries that are not regular files */
                if (dt->d_type != DT_REG)
			continue;

		/* ignore all entries that are not 32 bytes long */
		if (dt->d_reclen != 32)
			continue;

		/* set public key file path and store its content */
                n = strnlen(keyring, PATH_MAX);
                memset(path, 0, PATH_MAX);
                memcpy(path, keyring, n);
                path[n] = '/';
                memcpy(path+n+1, dt->d_name, dt->d_reclen);
		if ((key = fopen(path, "r")) == NULL) {
			perror(path);
			continue;
		}
		if (fread(pub, 1, 32, key) < 32) {
			perror(path);
			fclose(key);
			continue;
		}

		/* check message for the given public key */
		ret += ed25519_verify(sig, msg, len, pub);
		if (ret) {
			if (verbose)
				fprintf(stderr, "Key match: %s\n", path);
			break;
		}
        }

        closedir(dirp);
	return !ret;
}

/*
 * Check the given stream against the key provided. If the stream pointer
 * supposed to hold the key is NULL, check the stream against all public keys
 * located in the $KEYRING directory.
 */
static int
check(FILE *fp, FILE *key)
{
	int ret = 0;
	size_t len;
	char *buf = NULL;
	unsigned char *sig, *msg, pub[32];

	if ((len = bufferize(&buf, fp)) == 0)
		return ERR_NOMSG;

	if (verbose)
		fprintf(stderr, "Extracting signature from input\n");

	if (extractsig(&sig, buf, len) != 64) {
		if (verbose)
			fprintf(stderr, "ERROR: No valid signature found\n");

		free(buf);
		return ERR_NOSIG;
	}

	if ((len = extractmsg(&msg, buf, len)) == 0) {
		free(buf);
		free(sig);
	}

	if (verbose)
		fprintf(stderr, "Verifying stream (%lu bytes)\n", len);

	if (key) {
		if (fread(pub, 1, 32, key) < 32)
			return ERR_NOKEY;

		ret = !ed25519_verify(sig, msg, len, pub);
	} else {
		ret = check_keyring(sig, msg, len);
	}

	/*
	 * if we're able to verify the signature, dump buffer's content to
	 * stdout
	 */
	if (ret == 0)
		fwrite(msg, 1, len, stdout);

	if (verbose)
		fprintf(stderr, "Stream check %s\n", ret ? "FAILED" : "OK");

	free(msg);
	free(buf);
	free(sig);

	return ret;
}

/*
 * Remove a signature from a stream, and dump it to stdout
 */
static int
trimsig(FILE *fp)
{
	size_t len = 0;
	char *buf = NULL;
	unsigned char *msg = NULL;

	len = bufferize(&buf, fp);
	if (!buf)
		return -1;

	len = extractmsg(&msg, buf, len);
	if (!msg) {
		free(buf);
		return ERR_NOMSG;
	}

	fwrite(msg, 1, len, stdout);

	free(buf);
	free(msg);

	return 0;
}

int
main(int argc, char *argv[])
{
	int ret = 0, action = ACT_CHCK;
	FILE *key = NULL, *fp = NULL;

	ARGBEGIN{
	case 'f':
		key = fopen(EARGF(usage()), "r");
		break;
	case 'g':
		return createkeypair(EARGF(usage()));
		break; /* NOTREACHED */
	case 's':
		action = ACT_SIGN;
		break;
	case 't':
		action = ACT_TRIM;
		break;
	case 'v':
		verbose = 1;
		break;
	default:
		usage();
	}ARGEND;

	/* if no argument is provided, read stdin */
	fp = argc ? fopen(*argv, "r") : stdin;

	switch (action) {
	case ACT_SIGN:
		ret |= sign(fp, key);
		break;
	case ACT_CHCK:
		ret |= check(fp, key);
		break;
	case ACT_TRIM:
		ret |= trimsig(fp);
		break;
	}

	fclose(fp);
	if (key)
		fclose(key);

	return ret;
}
