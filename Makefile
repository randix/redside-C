# Copyright (c) 2013, Dowhaus Systems, LLC
# All rights reserved.

all: securesync dec settings rebuild

#enc: enc.c symcrypt.o settings.o
#	cc -o enc enc.c symcrypt.o settings.o -lz

install:
	mv securesync ~/bin/

securesync: \
            actions.o \
            crypt.o \
            db.o \
            file.o \
            main.o \
            settings.o \
            symcrypt.o \
            util.o
	cc -o securesync \
            actions.o \
            crypt.o \
            db.o \
            file.o \
            main.o \
            settings.o \
            symcrypt.o \
            util.o \
            -lz

settings: settings.c symcrypt.h securesync.h symcrypt.o
	cc -o settings -DUNIT_TEST settings.c symcrypt.o -lz

rebuild: rebuild.c securesync.h settings.o file.o db.o symcrypt.o util.o
	cc -o rebuild rebuild.c settings.o file.o db.o symcrypt.o util.o -lz

dec: dec.c symcrypt.o settings.o
	cc -o dec dec.c symcrypt.o settings.o -lz


actions.o: actions.c securesync.h symcrypt.h
crypt.o: crypt.c securesync.h symcrypt.h
db.o: db.c securesync.h
file.o: file.c securesync.h
main.o: main.c securesync.h
settings.o: settings.c securesync.h symcrypt.h
symcrypt.o: symcrypt.c securesync.h symcrypt.h
util.o: util.c securesync.h

clean:
	rm -f *.o

clobber: clean
	rm -f securesync rebuild settings enc dec
