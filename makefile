flags   = -Wall -std=c99 -D_GNU_SOURCE
dflags  = $(flags) -O0 -ggdb
rflags  = $(flags) -O3 -s -march=native
cflags  = -c -I/usr/include/mpi -DWL=64
ldflags = -lbrahe -lcurl -ljson -lpgapack-mpi1 -lmpi

objs = main rand ga

all: omgwtf

omgwtf: $(objs:%=%-r.o)
	gcc -o $@ $^ $(ldflags) $(rflags)
omgwtf-d: $(objs:%=%-d.o)
	gcc -o $@ $^ $(ldflags) $(dflags)

%-r.o: %.c makefile
	gcc -o $@ $< $(cflags) $(rflags)
%-d.o: %.c makefile
	gcc -o $@ $< $(cflags) $(dflags)

clean:
	rm -f omgwtf* *.o *~
	rm -rf code

