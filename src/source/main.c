
/* rypto main program */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "aes.h"

char *usage = "Usage: rypto <mode> <key> <infile> <outfile>\n  <mode> = e|d\n  <key> = 32 hex digits\n";

int debug = 0;

/* encrypt and PKCS#7 pad. */

void do_encrypt(AES_word *w, FILE *infile, FILE *outfile) {
  int i, n, n_read, n_written, final, pad;
  AES_byte in[16], out[16];

  final = 0;
  n_read = 0;
  n_written = 0;
  while (1) {
    n = fread (in, 1, 16, infile);
    n_read += n;
    if (n < 16) {
      /* final block - pad it (PKCS#7) */
      final = 1;
      pad = 16 - n;
      for (i = 15; i >= n; i --) {
	in[i] = pad;
	if (debug) printf ("padding: in[%d] = %02x\n", i, in[i]);
      }
    }
    AES_encrypt(in, out, w);
    if (fwrite(out, 1, 16, outfile) != 16) {
      perror("Error: fwrite");
      exit (6);
    }
    n_written += 16;
    if (final) {
      return;
    }
  }
}

/* decrypt, remove padding */

void do_decrypt(AES_word *w, FILE *infile, FILE *outfile) {
  int i, n, n_read, n_written, final, pad;
  off_t fpos;
  AES_byte in[16], out[16];

  final = 0;
  n_read = 0;
  n_written = 0;
  while (1) {
    n = fread (in, 1, 16, infile);
    if (n == 0) {
      if (n_read == 0) {
	/* special case: empty input */
	return;
      }
      /* the previous block was the last one,
	 just truncate the outfile so that padding is discarded */
      pad = out[15];
      if (pad > 16 || pad < 1) {
	fprintf(stderr, "Error: 1 > Pad (%d) > 16\n", pad);
	exit (8);
      }
      if (debug) printf ("padding: pad = %d\n", pad);
      fpos = ftello(outfile);
      if (fpos == -1) {
	perror("ftello");
	exit (9);
      }
      if (debug) printf ("padding: fpos before = %ld\n", fpos);
      fpos -= pad;
      if (debug) printf ("padding: fpos after = %ld\n", fpos);
      if (ftruncate(fileno(outfile), fpos) == -1) {
	perror("ftruncate");
	exit (10);
      }
      return;
    }
    if (n != 16) {
      fprintf(stderr, "Error: fread returned != 16 (%d)\n", n);
      perror(NULL);
      exit (11);
    }
    n_read += n;
    AES_decrypt(out, in, w);
    if (fwrite(out, 1, 16, outfile) != 16) {
      perror("Error: fwrite");
      exit (12);
    }
    n_written += n;
  }
}  

int main(int argc, char** argv) {
  int encrypt;
  int i, n, n_read, n_written, final, pad_needed;
  int key_error = 0;
  FILE *infile, *outfile;
  AES_byte key[16];
  AES_word w[44];
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
    if (debug) printf("key[%d] = %02x\n", i, key[i]);
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

  AES_KeyExpansion(key, w);
  if (encrypt) {
    do_encrypt(w, infile, outfile);
  } else {
    do_decrypt(w, infile, outfile);
  }

  fclose(infile);
  fclose(outfile);
  
}

