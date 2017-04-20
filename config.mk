VERSION = 1.1

CC = cc
LD = ${CC}

PREFIX = /usr/local
MANDIR = ${PREFIX}/man

CPPFLAGS = -I./ed25519/src -DVERSION=\"${VERSION}\"
CFLAGS = ${CPPFLAGS} -Wall -Wextra -pedantic
LDFLAGS =
LIBS =
