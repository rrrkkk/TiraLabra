
/* rypto main program */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "aes.h"

char *usage = "Usage: rypto <mode> <key> <infile> <outfile>\n  <mode> = e|d\n  <key> = 32 hex digits\n";

int debug = 0;

int main(int argc, char** argv) {
  int encrypt;
  int i;
  int key_error = 0;
  FILE *infile, *outfile;
  AES_byte key[16];
  AES_word w[44];
  AES_byte plaintext[16], ciphertext[16];
  char tmp[3];

  if (argc != 5) {
    fprintf (stderr, "%s", usage);
    exit (1);
  }

  if (strcmp (argv[1], "e") == 0) {
    encrypt = 1;
  } else if (strcmp (argv[1], "d") == 0) {
    encrypt = 0;
  } else {
    fprintf (stderr, "Error: <mode> must be either e or d\n");
    exit (2);
  }

  if (strlen (argv[2]) != 32) {
    key_error = 1;
  }
  for (i = 0; i < 32; i ++) {
    if (! isxdigit(argv[2][i])) {
      key_error = 1;
    }
  }
  if (key_error) {
    fprintf (stderr, "Error: <key> must be 32 hexadecimal characters\n");
    exit (3);
  }
  for (i = 0; i < 16; i ++) {
    strncpy(tmp, &argv[2][i * 2], 2);
    tmp[2] = 0;
    key[i] = (AES_byte) strtoul(tmp, NULL, 16);
    if (debug) { printf("key[%d] = %02x\n", i, key[i]); }
  }

  infile = fopen(argv[3], "r");
  if (infile == NULL) {
    fprintf(stderr, "Error: Cannot open infile %s for reading: ", argv[3]);
    perror(NULL);
    exit (4);
  }
  
  outfile = fopen(argv[4], "w");
  if (outfile == NULL) {
    fprintf(stderr, "Error: Cannot open outfile %s for writing: ", argv[4]);
    perror(NULL);
    exit (5);
  }
  
}

