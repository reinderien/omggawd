/*

   stompy testcase: stdlib random() LFSR
   -------------------------------------

   Copyright (C) 2007 by Michal Zalewski <lcamtuf@coredump.cx>

*/                                         

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  int i;
  for (i=0; i<20000; i++) 
    printf("%08x\n", random());
  return 0;
}
