flags   = -Wall -std=c99 -O0 -ggdb
#flags  = -Wall -std=c99 -O3 -march=native
cflags  = $(flags) -c
ldflags = $(flags) -lbrahe -lcurl -ljson

all: omgwtf

omgwtf: main.o testrand.o
	gcc -o $@ $^ $(ldflags)

%.o: %.c makefile
	gcc -o $@ $< $(cflags)

clean:
	rm -f omgwtf *.o *~

