/*

   stompy testcase: stdlib rand() LCG
   ----------------------------------

   Copyright (C) 2007 by Michal Zalewski <lcamtuf@coredump.cx>

*/                                         

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  int i;
  for (i=0; i<20000; i++) 
    printf("%08x\n", rand());
  return 0;
}
