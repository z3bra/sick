include config.mk

ED25519_SRC = ed25519/src/add_scalar.c \
	ed25519/src/fe.c \
	ed25519/src/ge.c \
	ed25519/src/key_exchange.c \
	ed25519/src/keypair.c \
	ed25519/src/sc.c \
	ed25519/src/seed.c \
	ed25519/src/sha512.c \
	ed25519/src/sign.c \
	ed25519/src/verify.c

SRC = sick.c base64.c ${ED25519_SRC}
OBJ = $(patsubst %.c,%.o,$(SRC))

sick: ${OBJ}
	${LD} -o sick ${OBJ} ${LDFLAGS} ${LIBS}

clean:
	rm -f ${OBJ} sick

install: sick
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp sick ${DESTDIR}${PREFIX}/bin/sick
	chmod 755 ${DESTDIR}${PREFIX}/bin/sick
	mkdir -p ${DESTDIR}${MANDIR}/man1
	cp sick.1 ${DESTDIR}${MANDIR}/man1/sick.1
	chmod 644 ${DESTDIR}${MANDIR}/man1/sick.1

uninstall:
	rm ${DESTDIR}${PREFIX}/bin/sick
	rm ${DESTDIR}${MANDIR}/man1/sick.1
