#
# Test cases for stompy - Makefile
# --------------------------------
#
# (C) Copyright 2007 by Michal Zalewski <lcamtuf@coredump.cx>
#

CFLAGS = -Wall -O3
BINS   = lcg-rand lfsr-rand urandom mtwister

all: $(BINS)

test: tests

tests: all
	cd ..; make stompy
	rm -f stompy-*.out
	for i in $(BINS); do ./$$i >$$i.out;../stompy -R $$i.out;done

clean:
	rm -f $(BINS) *.out core stompy-*.out


