#include <stdio.h> 


int main ()
{

  int d;

  d = puts ("\x00");
  printf ("a: %d\n", d);

  d = puts ("");
  printf ("a: %d\n", d);

  d = puts ("   ");
  printf ("a: %d\n", d);
}

