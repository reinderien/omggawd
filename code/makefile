all: libexample.so host

libexample.so: example.c makefile
	gcc -o $@ $< -fpic -shared -nostdinc -nostdlib
host: host.c libexample.so makefile
	gcc -o $@ $< -l:./libexample.so
