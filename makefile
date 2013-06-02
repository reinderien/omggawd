flags   = -Wall -std=c99 -D_GNU_SOURCE -O0 -ggdb
#flags  = -Wall -std=c99 -D_GNU_SOURCE -O3 -march=native
cflags  = $(flags) -c
ldflags = $(flags) -lbrahe -lcurl -ljson

all: omgwtf

omgwtf: main.o testrand.o
	gcc -o $@ $^ $(ldflags)

%.o: %.c makefile
	gcc -o $@ $< $(cflags)

clean:
	rm -f omgwtf *.o *~

