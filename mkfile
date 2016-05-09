<config.mk

ED25519_SRC = `{find ed25519/src -name '*.c'}

SRC = sick.c base64.c ${ED25519_SRC}
OBJ = ${SRC:%.c=%.o}

sick: $OBJ
	${CC} $OBJ ${LDFLAGS} ${LIBS} -o sick

%.o: %.c
	${CC} ${CFLAGS} -c $stem.c -o $stem.o

clean:V:
	rm -f $OBJ sick

install:V: sick
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp sick ${DESTDIR}${PREFIX}/bin/sick
	chmod 755 ${DESTDIR}${PREFIX}/bin/sick
	mkdir -p ${DESTDIR}${MANDIR}/man1
	cp sick.1 ${DESTDIR}${MANDIR}/man1/sick.1
	chmod 644 ${DESTDIR}${MANDIR}/man1/sick.1

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/sick
	rm ${DESTDIR}${MANDIR}/man1/sick.1
