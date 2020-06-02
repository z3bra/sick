<config.mk

ED25519_SRC = `{find ed25519/src -name '*.c'}

SRC = sick.c base64.c $ED25519_SRC
OBJ = ${SRC:%.c=%.o}

sick: $OBJ
	$LD -o $target $prereq $LDFLAGS $LIBS

%.o: %.c
	$CC $CFLAGS -c $stem.c -o $stem.o

clean:V:
	rm -f $OBJ sick

install:V: sick
	mkdir -p ${DESTDIR}${PREFIX}/bin
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	cp sick ${DESTDIR}${PREFIX}/bin/sick
	cp sick.1 ${DESTDIR}${MANPREFIX}/man1/sick.1
	chmod 755 ${DESTDIR}${PREFIX}/bin/sick

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/sick
	rm ${DESTDIR}${MANPREFIX}/man1/sick.1
