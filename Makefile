# Copyright (c) 2013, Dowhaus Systems, LLC
# All rights reserved.

all: redside settings

#enc: enc.c symcrypt.o settings.o
#	cc -o enc enc.c symcrypt.o settings.o -lz

install:
	mv redside ~/bin/

redside: \
            actions.o \
            crypt.o \
            db.o \
            file.o \
            main.o \
            settings.o \
            symcrypt.o \
            util.o
	cc -o redside \
            actions.o \
            crypt.o \
            db.o \
            file.o \
            main.o \
            settings.o \
            symcrypt.o \
            util.o \
            -lz

settings: settings.c symcrypt.h redside.h symcrypt.o
	cc -o settings -DUNIT_TEST settings.c symcrypt.o -lz

rebuild: rebuild.c redside.h settings.o file.o db.o symcrypt.o util.o
	cc -o rebuild rebuild.c settings.o file.o db.o symcrypt.o util.o -lz

dec: dec.c symcrypt.o settings.o
	cc -o dec dec.c symcrypt.o settings.o -lz


actions.o: actions.c redside.h symcrypt.h
crypt.o: crypt.c redside.h symcrypt.h
db.o: db.c redside.h
file.o: file.c redside.h
main.o: main.c redside.h
settings.o: settings.c redside.h symcrypt.h
symcrypt.o: symcrypt.c redside.h symcrypt.h
util.o: util.c redside.h

clean:
	rm -f *.o

clobber: clean
	rm -f redside rebuild settings enc dec
