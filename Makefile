EXE		= uif2iso
CFLAGS	+= -O2 -s
PREFIX	= /usr/local
BINDIR	= $(PREFIX)/bin
SRC		= $(EXE).c
LIBS	= -lz -lssl -lcrypto

all:
	$(CC) $(SRC) $(CFLAGS) -o $(EXE) $(LIBS)

install:
	install -m 755 -d $(BINDIR)
	install -m 755 $(EXE) $(BINDIR)/$(EXE)

.PHONY:
	install
