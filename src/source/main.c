
/* rypto main program */

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "aes.h"

char *usage = "Usage: rypto <mode> <key> <infile> <outfile>\n  <mode> = e|d\n  <key> = 32 hex digits\n";

/* make this 1 to have (boring) debug output*/
int debug = 0;

/* make this 1 to count and print resource usage */
int stats = 0;

/* helper for the following, encrypt 1 block, write it to file. */

void encrypt_and_write (AES_byte *in, AES_word *w, FILE *outfile)
{
  AES_byte out[16];
  
  AES_encrypt(in, out, w);
  if (fwrite(out, 1, 16, outfile) != 16) {
    perror("Error: fwrite");
    exit (6);
  }
}

/* encrypt and PKCS#7 pad. */

void do_encrypt(AES_word *w, FILE *infile, FILE *outfile,
		off_t *n_read_ptr, off_t *n_written_ptr)
{
  int i, n, pad;
  off_t n_read, n_written;
  AES_byte in[16];

  n_read = 0;
  n_written = 0;
  while (1) {
    n = fread (in, 1, 16, infile);
    n_read += n;
    if (n < 16) {
      /* final block */
      break;
    }
    encrypt_and_write(in, w, outfile);
    n_written += 16;
  } /* while */
      
  /* final block
     may be 0-15 bytes
     pad it (PKCS#7) before encryption */
  pad = 16 - n;
  for (i = 15; i >= n; i --) {
    in[i] = pad;
    if (debug) printf ("padding: in[%d] = %02x\n", i, in[i]);
  }
  encrypt_and_write(in, w, outfile);
  n_written += 16;

  /* report work done and go back */
  *n_read_ptr = n_read;
  *n_written_ptr = n_written;
  return;

}

/* decrypt, remove padding.
   return the length of final file. */

off_t do_decrypt(AES_word *w, FILE *infile, FILE *outfile,
		 off_t *n_read_ptr, off_t *n_written_ptr)
{
  int i, n, final, pad;
  off_t n_read, n_written;
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
	*n_read_ptr = 0;
	*n_written_ptr = 0;
	return 0;
      }
      /* the previous block was the last */
      break;
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
    n_written += 16;
  }
  
  /* the previous block was the last one. 
     instruct parent to truncate the outfile so that padding is discarded */
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
  n_written -= pad;
  if (debug) printf ("padding: fpos after = %ld\n", fpos);
  /* ftruncate(2) below failed on melkki. so:
   * return correct offset and truncate(2) in the main,
   * after the file has been closed. 
   * if (ftruncate(fileno(outfile), fpos) == -1) {
   *   perror("ftruncate");
   *   exit (10);
   * }
   */
  *n_read_ptr = n_read;
  *n_written_ptr = n_written;
  return fpos;

}

/* helper for below. check and parse key. */

void parse_key(char *cmdline_key, AES_byte *key)
{
  int i;
  int key_error = 0;
  char tmp[3];

  if (strlen (cmdline_key) != 32) {
    key_error = 1;
  } else {
    for (i = 0; i < 32; i ++) {
      if (! isxdigit(cmdline_key[i])) {
	key_error = 1;
	break;
      }
    }
  }
  if (key_error) {
    fprintf (stderr, "Error: <key> must be 32 hexadecimal characters\n");
    exit (3);
  }
  for (i = 0; i < 16; i ++) {
    strncpy(tmp, &cmdline_key[i * 2], 2);
    tmp[2] = 0;
    key[i] = (AES_byte) strtoul(tmp, NULL, 16);
    if (debug) printf("key[%d] = %02x\n", i, key[i]);
  }

}

int main(int argc, char** argv) {
  int encrypt;
  FILE *infile, *outfile;
  AES_byte key[16];
  AES_word w[44];
  off_t n_read, n_written, fpos;
  char *cmdline_mode, *cmdline_key, *cmdline_infile, *cmdline_outfile;
  struct rusage r_usage;

  if (argc != 5) {
    fprintf (stderr, "%s", usage);
    exit (1);
  }

  cmdline_mode = argv[1];
  cmdline_key = argv[2];
  cmdline_infile = argv[3];
  cmdline_outfile = argv[4];

  if (strcmp (cmdline_mode, "e") == 0) {
    encrypt = 1;
  } else if (strcmp (cmdline_mode, "d") == 0) {
    encrypt = 0;
  } else {
    fprintf (stderr, "Error: <mode> must be either e or d\n");
    exit (2);
  }

  parse_key(cmdline_key, key);

  /* this does not take e.g. symlinks or hard links into account */
  if (strcmp(cmdline_infile, cmdline_outfile) == 0) {
    fprintf(stderr, "Error: infile %s and outfile %s cannot be the same\n",
	    cmdline_infile, cmdline_outfile);
    exit (4);
  }
  
  infile = fopen(cmdline_infile, "r");
  if (infile == NULL) {
    fprintf(stderr, "Error: Cannot open infile %s for reading: ", cmdline_infile);
    perror(NULL);
    exit (4);
  }
  
  outfile = fopen(cmdline_outfile, "w");
  if (outfile == NULL) {
    fprintf(stderr, "Error: Cannot open outfile %s for writing: ", cmdline_outfile);
    perror(NULL);
    exit (5);
  }

  AES_KeyExpansion(key, w);
  if (encrypt) {
    do_encrypt(w, infile, outfile, &n_read, &n_written);
    fclose(infile);
    fclose(outfile);
  } else {
    fpos = do_decrypt(w, infile, outfile, &n_read, &n_written);
    fclose(infile);
    fclose(outfile);
    if (truncate(cmdline_outfile, fpos) != 0) { /* a bootleg fix */
      perror("truncate");
      /* in this case, let's just fall thru */
    }
  }

  if (stats) {
    printf("file i/o: %ld bytes read, %ld bytes written\n", n_read, n_written);

    getrusage(RUSAGE_SELF, &r_usage);
    printf("times: user %d.%06d, system %d.%06d\n",
	   r_usage.ru_utime.tv_sec, r_usage.ru_utime.tv_usec, 
	   r_usage.ru_stime.tv_sec, r_usage.ru_stime.tv_usec);
  }

  exit(0);
  
}

