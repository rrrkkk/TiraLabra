
/* AES implementation.

   Riku Kalinen 2017 */

#include "aes.h"

#include "aes_tables.h" /* static tables here */

/* Unrecoverable error, bail out */

void AES_KaBoom(char *curse) {
  fprintf(stderr, "%s\n", curse);
  exit(1);
}

/* Help function to create one word from 4 bytes. */

AES_word AES_makeword(AES_byte b0, AES_byte b1, AES_byte b2, AES_byte b3) {
  return (AES_word) b0 << 24 | (AES_word) b1 << 16 | (AES_word) b2 << 8 | (AES_word) b3; 
}

/* KeyExpansion helpers, from the standard, pp. 19. */

AES_word AES_SubWord(AES_word w) {
  AES_word r; /* result */
  
  r = (AES_word) AES_S_Box[w & 0x000000FF]
    | (AES_word) (AES_S_Box[(w >> 8) & 0x000000FF]) << 8
    | (AES_word) (AES_S_Box[(w >> 16) & 0x000000FF]) << 16
    | (AES_word) (AES_S_Box[(w >> 24) & 0x000000FF]) << 24;

  return r;
}

AES_word AES_RotWord(AES_word w) {
  AES_word r; /* result */

  r = (w >> 24) | (w << 8); 
  
  return r;
}

/* Generate a key schedule from key (16 bytes) to w.
   Limited to 128-bit keys. => Nk, Nr are constant */

void AES_KeyExpansion(AES_byte *key, AES_word *w) {
  AES_word temp;
  int i;

  if (AES_Nk != 4) {
    AES_KaBoom("AES_KeyExpansion: Nk != 4");
  }

  for (i = 0; i < AES_Nk; i ++) {
    w[i] = AES_makeword(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
  }

  for (i = AES_Nk; i < AES_Nb * (AES_Nr + 1); i ++) {
    temp = w[i - 1];
    if (i % AES_Nk == 0) {
      temp = AES_SubWord(AES_RotWord(temp)) ^ AES_Rcon[i/AES_Nk];
    } else if (AES_Nk > 6 && i % AES_Nk == 4) {
      /* this part of the code not relevant for us, AES_Nk == 4.
	 hopefully optimizer takes this away. */
      temp = AES_SubWord(temp);
    } /* if */
    w[i] = w[i-AES_Nk] ^ temp;
  }

  return;
}

/* Note that state columns and rows are reversed from the standard
   in all helper functions below.
   e.g. when standard refers to state[x,y], we use state[y][x] */

/* AddRoundKey - transformation. Standard pp. 18- */

void AES_AddRoundKey(AES_byte state[AES_Nb][4], AES_word *w) {
  AES_byte b[4]; /* individual bytes of each word. endianness. */
  int i, j;
  for (i = 0; i < AES_Nb; i ++) {
    b[0] = w[i] >> 24;
    b[1] = (w[i] >> 16) & 0xff;
    b[2] = (w[i] >> 8) & 0xff;
    b[3] = w[i] & 0xff;
    /* printf("AddRoundKey: i=%d, b[0]=%x, b[1]=%x, b[2]=%x, b[3]=%x\n",
       i, b[0], b[1], b[2], b[3]); */
    for (j = 0; j < 4; j ++) {
      /* printf("AddRoundKey: j=%d, state before=%x", j, state[i][j]); */
      state[i][j] ^= b[j];
      /* printf(", state after=%x\n", state[i][j]); */
    } /* for j */
  } /* for i */
} /* AES_AddRoundKey */

/* SubBytes transformation. Standard pp. 15 */

void AES_SubBytes(AES_byte state[AES_Nb][4]) {
  int i, j;
  for (i = 0; i < AES_Nb; i ++) {
    for (j = 0; j < 4; j ++) {
      state[j][i] = AES_S_Box[state[j][i]];
    }
  }
}

/* InvSubBytes transformation. Standard pp. 22 */

void AES_InvSubBytes(AES_byte state[AES_Nb][4]) {
  int i, j;
  for (i = 0; i < AES_Nb; i ++) {
    for (j = 0; j < 4; j ++) {
      state[j][i] = AES_inverse_S_Box[state[j][i]];
    }
  }
}

/* ShiftRows transformation. Standard pp. 17 */

void AES_ShiftRows(AES_byte state[AES_Nb][4]) {
  AES_byte b0, b1;

  /* row 0: NOP */
  /* row 1 */
  b0 = state[0][1];
  state[0][1] = state[1][1];
  state[1][1] = state[2][1];
  state[2][1] = state[3][1];
  state[3][1] = b0;
  /* row 2 */
  b0 = state[0][2];
  b1 = state[1][2];
  state[0][2] = state[2][2];
  state[1][2] = state[3][2];
  state[2][2] = b0;
  state[3][2] = b1;
  /* row 3 */
  b0 = state[0][3];
  state[0][3] = state[3][3];
  state[3][3] = state[2][3];
  state[2][3] = state[1][3];
  state[1][3] = b0;
 
}

/* InvShiftRows transformation. Standard pp. 21 */

void AES_InvShiftRows(AES_byte state[AES_Nb][4]) {
  AES_byte b0, b1;

  /* row 0: NOP */
  /* row 1 */
  b0 = state[3][1];
  state[3][1] = state[2][1];
  state[2][1] = state[1][1];
  state[1][1] = state[0][1];
  state[0][1] = b0;
  /* row 2 */
  b0 = state[2][2];
  b1 = state[3][2];
  state[2][2] = state[0][2];
  state[3][2] = state[1][2];
  state[0][2] = b0;
  state[1][2] = b1;
  /* row 3 */
  b0 = state[3][3];
  state[3][3] = state[0][3];
  state[0][3] = state[1][3];
  state[1][3] = state[2][3];
  state[2][3] = b0;
 
}

/* MixColumns transformation. Standard pp. 17 */

void AES_MixColumns(AES_byte state[AES_Nb][4]) {
  AES_byte b0, b1, b2, b3;

  b0 = state[0][0];
  b1 = state[0][1];
  b2 = state[0][2];
  b3 = state[0][3];
  state[0][0] = AES_g_m[0][b0];
  state[0][0] ^= AES_g_m[1][b1];
  state[0][0] ^= b2;
  state[0][0] ^= b3;
  state[0][1] = b0;
  state[0][1] ^= AES_g_m[0][b1];
  state[0][1] ^= AES_g_m[1][b2];
  state[0][1] ^= b3;
  state[0][2] = b0;
  state[0][2] ^= b1;
  state[0][2] ^= AES_g_m[0][b2];
  state[0][2] ^= AES_g_m[1][b3];
  state[0][3] = AES_g_m[1][b0];
  state[0][3] ^= b1;
  state[0][3] ^= b2;
  state[0][3] ^= AES_g_m[0][b3];

  b0 = state[1][0];
  b1 = state[1][1];
  b2 = state[1][2];
  b3 = state[1][3];
  state[1][0] = AES_g_m[0][b0];
  state[1][0] ^= AES_g_m[1][b1];
  state[1][0] ^= b2;
  state[1][0] ^= b3;
  state[1][1] = b0;
  state[1][1] ^= AES_g_m[0][b1];
  state[1][1] ^= AES_g_m[1][b2];
  state[1][1] ^= b3;
  state[1][2] = b0;
  state[1][2] ^= b1;
  state[1][2] ^= AES_g_m[0][b2];
  state[1][2] ^= AES_g_m[1][b3];
  state[1][3] = AES_g_m[1][b0];
  state[1][3] ^= b1;
  state[1][3] ^= b2;
  state[1][3] ^= AES_g_m[0][b3];

  b0 = state[2][0];
  b1 = state[2][1];
  b2 = state[2][2];
  b3 = state[2][3];
  state[2][0] = AES_g_m[0][b0];
  state[2][0] ^= AES_g_m[1][b1];
  state[2][0] ^= b2;
  state[2][0] ^= b3;
  state[2][1] = b0;
  state[2][1] ^= AES_g_m[0][b1];
  state[2][1] ^= AES_g_m[1][b2];
  state[2][1] ^= b3;
  state[2][2] = b0;
  state[2][2] ^= b1;
  state[2][2] ^= AES_g_m[0][b2];
  state[2][2] ^= AES_g_m[1][b3];
  state[2][3] = AES_g_m[1][b0];
  state[2][3] ^= b1;
  state[2][3] ^= b2;
  state[2][3] ^= AES_g_m[0][b3];

  b0 = state[3][0];
  b1 = state[3][1];
  b2 = state[3][2];
  b3 = state[3][3];
  state[3][0] = AES_g_m[0][b0];
  state[3][0] ^= AES_g_m[1][b1];
  state[3][0] ^= b2;
  state[3][0] ^= b3;
  state[3][1] = b0;
  state[3][1] ^= AES_g_m[0][b1];
  state[3][1] ^= AES_g_m[1][b2];
  state[3][1] ^= b3;
  state[3][2] = b0;
  state[3][2] ^= b1;
  state[3][2] ^= AES_g_m[0][b2];
  state[3][2] ^= AES_g_m[1][b3];
  state[3][3] = AES_g_m[1][b0];
  state[3][3] ^= b1;
  state[3][3] ^= b2;
  state[3][3] ^= AES_g_m[0][b3];
  
}

/* InvMixColumns transformation. Standard pp. 23 */

void AES_InvMixColumns(AES_byte state[AES_Nb][4]) {
  AES_byte b0, b1, b2, b3;

  b0 = state[0][0];
  b1 = state[0][1];
  b2 = state[0][2];
  b3 = state[0][3];
  state[0][0] = AES_g_m[5][b0];
  state[0][0] ^= AES_g_m[3][b1];
  state[0][0] ^= AES_g_m[4][b2];
  state[0][0] ^= AES_g_m[2][b3];
  state[0][1] = AES_g_m[2][b0];
  state[0][1] ^= AES_g_m[5][b1];
  state[0][1] ^= AES_g_m[3][b2];
  state[0][1] ^= AES_g_m[4][b3];
  state[0][2] = AES_g_m[4][b0];
  state[0][2] ^= AES_g_m[2][b1];
  state[0][2] ^= AES_g_m[5][b2];
  state[0][2] ^= AES_g_m[3][b3];
  state[0][3] = AES_g_m[3][b0];
  state[0][3] ^= AES_g_m[4][b1];
  state[0][3] ^= AES_g_m[2][b2];
  state[0][3] ^= AES_g_m[5][b3];

  b0 = state[1][0];
  b1 = state[1][1];
  b2 = state[1][2];
  b3 = state[1][3];
  state[1][0] = AES_g_m[5][b0];
  state[1][0] ^= AES_g_m[3][b1];
  state[1][0] ^= AES_g_m[4][b2];
  state[1][0] ^= AES_g_m[2][b3];
  state[1][1] = AES_g_m[2][b0];
  state[1][1] ^= AES_g_m[5][b1];
  state[1][1] ^= AES_g_m[3][b2];
  state[1][1] ^= AES_g_m[4][b3];
  state[1][2] = AES_g_m[4][b0];
  state[1][2] ^= AES_g_m[2][b1];
  state[1][2] ^= AES_g_m[5][b2];
  state[1][2] ^= AES_g_m[3][b3];
  state[1][3] = AES_g_m[3][b0];
  state[1][3] ^= AES_g_m[4][b1];
  state[1][3] ^= AES_g_m[2][b2];
  state[1][3] ^= AES_g_m[5][b3];

  b0 = state[2][0];
  b1 = state[2][1];
  b2 = state[2][2];
  b3 = state[2][3];
  state[2][0] = AES_g_m[5][b0];
  state[2][0] ^= AES_g_m[3][b1];
  state[2][0] ^= AES_g_m[4][b2];
  state[2][0] ^= AES_g_m[2][b3];
  state[2][1] = AES_g_m[2][b0];
  state[2][1] ^= AES_g_m[5][b1];
  state[2][1] ^= AES_g_m[3][b2];
  state[2][1] ^= AES_g_m[4][b3];
  state[2][2] = AES_g_m[4][b0];
  state[2][2] ^= AES_g_m[2][b1];
  state[2][2] ^= AES_g_m[5][b2];
  state[2][2] ^= AES_g_m[3][b3];
  state[2][3] = AES_g_m[3][b0];
  state[2][3] ^= AES_g_m[4][b1];
  state[2][3] ^= AES_g_m[2][b2];
  state[2][3] ^= AES_g_m[5][b3];

  b0 = state[3][0];
  b1 = state[3][1];
  b2 = state[3][2];
  b3 = state[3][3];
  state[3][0] = AES_g_m[5][b0];
  state[3][0] ^= AES_g_m[3][b1];
  state[3][0] ^= AES_g_m[4][b2];
  state[3][0] ^= AES_g_m[2][b3];
  state[3][1] = AES_g_m[2][b0];
  state[3][1] ^= AES_g_m[5][b1];
  state[3][1] ^= AES_g_m[3][b2];
  state[3][1] ^= AES_g_m[4][b3];
  state[3][2] = AES_g_m[4][b0];
  state[3][2] ^= AES_g_m[2][b1];
  state[3][2] ^= AES_g_m[5][b2];
  state[3][2] ^= AES_g_m[3][b3];
  state[3][3] = AES_g_m[3][b0];
  state[3][3] ^= AES_g_m[4][b1];
  state[3][3] ^= AES_g_m[2][b2];
  state[3][3] ^= AES_g_m[5][b3];
  
}

/* encrypt. standard, pp. 15 */

void AES_encrypt(AES_byte *plaintext, AES_byte *ciphertext, AES_word *w) {
  int i, j, k; /* indices to state and *text */
  int r; /* current round */
  AES_byte state[AES_Nb][4];
  
  k = 0;
  for (i = 0; i < AES_Nb; i ++) {
    for (j = 0; j < 4; j ++) {
      state[i][j] = plaintext[k];
      k ++;
    } /* for j */
  } /* for i */

  AES_AddRoundKey(state, w);
  
  for (r = 1; r < AES_Nr; r ++) {
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_MixColumns(state);
    AES_AddRoundKey(state, w + 4 * r);
  }

  AES_SubBytes(state);
  AES_ShiftRows(state);
  AES_AddRoundKey(state, w + 40);
  
  k = 0;
  for (i = 0; i < AES_Nb; i ++) {
    for (j = 0; j < 4; j ++) {
      ciphertext[k] = state[i][j];
      k ++;
    } /* for j */
  } /* for i */

}

/* decrypt. standard, pp. 21 */

void AES_decrypt(AES_byte *plaintext, AES_byte *ciphertext, AES_word *w) {
  int i, j, k; /* indices to state and *text */
  int r; /* current round */
  AES_byte state[AES_Nb][4];
  
  k = 0;
  for (i = 0; i < AES_Nb; i ++) {
    for (j = 0; j < 4; j ++) {
      state[i][j] = ciphertext[k];
      k ++;
    } /* for j */
  } /* for i */

  AES_AddRoundKey(state, w + 40);
  
  for (r = AES_Nr - 1; r > 0; r --) {
    AES_InvShiftRows(state);
    AES_InvSubBytes(state);
    AES_AddRoundKey(state, w + 4 * r);
    AES_InvMixColumns(state);
  }
  
  AES_InvShiftRows(state);
  AES_InvSubBytes(state);
  AES_AddRoundKey(state, w);
  
  k = 0;
  for (i = 0; i < AES_Nb; i ++) {
    for (j = 0; j < 4; j ++) {
      plaintext[k] = state[i][j];
      k ++;
    } /* for j */
  } /* for i */

}
