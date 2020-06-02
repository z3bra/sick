include config.mk

.POSIX:

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

SRC = sick.c base64.c $(ED25519_SRC)
OBJ = $(SRC:.c=.o)

sick: $(OBJ)
	$(LD) -o sick $(OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJ) sick

install: sick
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	cp sick.1 $(DESTDIR)$(MANPREFIX)/man1/sick.1
	cp sick $(DESTDIR)$(PREFIX)/bin/sick
	chmod 755 $(DESTDIR)$(PREFIX)/bin/sick

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/sick
	rm $(DESTDIR)$(MANPREFIX)/man1/sick.1
