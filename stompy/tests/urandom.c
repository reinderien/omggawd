/*

   stompy testcase: /dev/urandom MD5/Yarrow PRNG
   ---------------------------------------------

   Copyright (C) 2007 by Michal Zalewski <lcamtuf@coredump.cx>

*/                                         

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
  int i;
  int a = open("/dev/urandom",O_RDONLY);
  if (a < 0) { perror("/dev/urandom"); exit(1); }

  for (i=0; i<20000; i++) {
    unsigned int x;
    read(a,&x,4);
    printf("%08x\n", x);
  }
  return 0;
}
