# Genetic Algorithm WTF Decisionator
# (c) Greg Toombs 2013 (should I really put my name on this?)

flags   = -Wall -std=c99 -D_GNU_SOURCE
dflags  = $(flags) -O0 -ggdb
rflags  = $(flags) -O3 -s -march=native
cflags  = -c -I/usr/include/mpi -DWL=64
ldflags = -lcurl -ljson -lpgapack-mpi1 -lmpi -lm

all: main-r ga-r

main-r: main-r.o
	gcc -o $@ $^ $(ldflags) $(rflags)
main-d: main-d.o
	gcc -o $@ $^ $(ldflags) $(dflags)
ga-r: ga-r.o rand-r.o
	gcc -o $@ $^ $(ldflags) $(rflags)
ga-d: ga-d.o rand-d.o
	gcc -o $@ $^ $(ldflags) $(dflags)

%-r.o: %.c makefile
	gcc -o $@ $< $(cflags) $(rflags)
%-d.o: %.c makefile
	gcc -o $@ $< $(cflags) $(dflags)

clean:
	rm -f *-r *-d *.so *.o *~ stomped* awesome.c potentials.c

