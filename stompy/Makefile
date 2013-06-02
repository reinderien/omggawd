#
# stompy - Makefile
# -----------------
#
# (C) Copyright 2007 by Michal Zalewski <lcamtuf@coredump.cx>
#

CC      = gcc
CFLAGS  = -ffast-math -O3 -Wall -fomit-frame-pointer -funroll-loops -s -march=native
LIBS    = -lm -lgmp -lssl -lcrypto
FILE	= stompy

all: warning $(FILE)

warning:
	@echo "Note: GNU MP library version 4.1 or newer is required. Older versions will not work."

static: $(FILE)-static

$(FILE): $(FILE).c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(FILE)-static: $(FILE).c 
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -static

clean:
	rm -f core core.[0123456789]* *~ *.o $(FILE) a.out $(FILE)-static stompy-*.dat stompy-*.out
	cd tests; make clean

publish: clean
	cd ..;tar cfvz /tmp/stompy.tgz stompy
	scp -p /tmp/stompy.tgz lcamtuf@coredump.cx:/export/www/lcamtuf/stompy.tgz
	cat /tmp/stompy.tgz >~lcamtuf/stompy-bkup.tgz
	rm -f /tmp/stompy.tgz
	

install: $(FILE)
	cp -f $(FILE) /usr/sbin/

