#include "hashtopass.h"

void hashtopass(int numbers_only, char* p, size_t len, uint8_t* key)
{
  int i;
  char* numerals = "0123456789";

  if (numbers_only) {

    for (i = 0; i < len; i++)
      p[i] = numerals[key[i] % 10];

  } else {

    char* lowers = "abcdefghijklmnopqrstuvwxyz";
    char* uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char* allchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    p[0] = lowers[key[0] % 26];
    p[1] = numerals[key[1] % 10];
    p[2] = uppers[key[2] % 26];

    size_t i;
    for (i = 3; i < len; i++)
      p[i] = allchars[key[i] % (26 + 26 + 10)];
  }

  p[len] = '\0';

}