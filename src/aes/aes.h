
/* AES declarations.

   Riku Kalinen 2017 */

#include <stdio.h>
#include <sys/types.h>

typedef u_int8_t AES_byte;
typedef u_int32_t AES_word;

/* These are constant as we only implement 128-bit AES. */

#define AES_Nk 4
#define AES_Nr 10

/* This is constant in AES anyway */

#define AES_Nb 4

void AES_KaBoom(char *);
AES_word AES_makeword(AES_byte b0, AES_byte b1, AES_byte b2, AES_byte b3);
void AES_KeyExpansion(AES_byte *key, AES_word *w, int Nk);
