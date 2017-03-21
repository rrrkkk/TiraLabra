
/* AES declarations.

   Riku Kalinen 2017 */

#include <stdio.h>
#include <sys/types.h>

typedef u_int8_t AES_byte;
typedef u_int32_t AES_word;

void AES_KaBoom(char *);
void AES_KeyExpansion(AES_byte *key, AES_word *w, int Nk);
