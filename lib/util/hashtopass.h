#include "scrypt_platform.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "warn.h"

void hashtopass(int numbers_only, char* p, size_t len, uint8_t* key);