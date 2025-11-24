#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x100] = {0};
  printf("(^・ω・^§)ﾉ ");
  read(0, buf, 0xff);
  printf(buf);
  exit(0);
}

__attribute__((constructor)) void init() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(120);
}
