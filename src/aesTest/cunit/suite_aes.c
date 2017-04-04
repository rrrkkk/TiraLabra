#include <CUnit/Basic.h>
#include "gradle_cunit_register.h"
#include "aes.h"

int suite_init(void) {
    return 0;
}

int suite_clean(void) {
    return 0;
}

/* dummy tests to just check the toolchain is working. */

/* always successful */

void test_void(void) {
  CU_ASSERT(0 == 0);
}

/* always fails */

void test_fail(void) {
  CU_ASSERT(1 == 0);
}

/* makeword test case: 0x01, 0x02, 0x03, 0x04 -> 0x01020304 */

void test_makeword(void) {
  CU_ASSERT(AES_makeword(0x01, 0x02, 0x03, 0x04) == 0x01020304);
}

/* KeyExpansion test cases, from the Internet */

#define N_W 44 /* size of expanded key, in words */

void test_KeyExpansion_00(void) {
  int i;
  int passed = 1;
  AES_byte key[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  AES_word actual_w[N_W];
  AES_word expected_w[N_W] =
    { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x62636363, 0x62636363, 0x62636363, 0x62636363, 
      0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa, 
      0x90973450, 0x696ccffa, 0xf2f45733, 0x0b0fac99, 
      0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b, 
      0x7f2e2b88, 0xf8443e09, 0x8dda7cbb, 0xf34b9290, 
      0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7, 
      0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b, 
      0x0ef90333, 0x3ba96138, 0x97060a04, 0x511dfa9f, 
      0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941, 
      0xb4ef5bcb, 0x3e92e211, 0x23e951cf, 0x6f8f188e };

  AES_KeyExpansion(key, actual_w);
  for (i = 0; i < N_W; i ++)
    if (actual_w[i] != expected_w[i]) {
      printf("test_KeyExpansion_00 failed, i=%d, actual=%x, expected=%x\n",
	       i, actual_w[i], expected_w[i]);
      CU_FAIL("test_KeyExpansion_00 failed");
      passed = 0;
    }

  if (passed)
    CU_PASS("test_KeyExpansion_00 passed");
}

void test_KeyExpansion_ff(void) {
  int i;
  int passed = 1;
  AES_byte key[] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  AES_word actual_w[N_W];
  AES_word expected_w[N_W] =
    { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 
      0xe8e9e9e9, 0x17161616, 0xe8e9e9e9, 0x17161616, 
      0xadaeae19, 0xbab8b80f, 0x525151e6, 0x454747f0, 
      0x090e2277, 0xb3b69a78, 0xe1e7cb9e, 0xa4a08c6e, 
      0xe16abd3e, 0x52dc2746, 0xb33becd8, 0x179b60b6, 
      0xe5baf3ce, 0xb766d488, 0x045d3850, 0x13c658e6, 
      0x71d07db3, 0xc6b6a93b, 0xc2eb916b, 0xd12dc98d, 
      0xe90d208d, 0x2fbb89b6, 0xed5018dd, 0x3c7dd150, 
      0x96337366, 0xb988fad0, 0x54d8e20d, 0x68a5335d, 
      0x8bf03f23, 0x3278c5f3, 0x66a027fe, 0x0e0514a3, 
      0xd60a3588, 0xe472f07b, 0x82d2d785, 0x8cd7c326 };

  AES_KeyExpansion(key, actual_w);
  for (i = 0; i < N_W; i ++)
    if (actual_w[i] != expected_w[i]) {
      printf("test_KeyExpansion_ff failed, i=%d, actual=%x, expected=%x\n",
	       i, actual_w[i], expected_w[i]);
      CU_FAIL("test_KeyExpansion_ff failed");
      passed = 0;
    }

  if (passed)
    CU_PASS("test_KeyExpansion_ff passed");
}

void test_KeyExpansion_01(void) {
  int i;
  int passed = 1;
  AES_byte key[] =
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  AES_word actual_w[N_W];
  AES_word expected_w[N_W] =
    { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 
      0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe, 
      0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe, 
      0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41, 
      0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd, 
      0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa, 
      0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b, 
      0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026, 
      0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2, 
      0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e, 
      0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5 };

  AES_KeyExpansion(key, actual_w);
  for (i = 0; i < N_W; i ++)
    if (actual_w[i] != expected_w[i]) {
      printf("test_KeyExpansion_01 failed, i=%d, actual=%x, expected=%x\n",
	       i, actual_w[i], expected_w[i]);
      CU_FAIL("test_KeyExpansion_01 failed");
      passed = 0;
    }

  if (passed)
    CU_PASS("test_KeyExpansion_01 passed");
}

/* From standard, pp. 27 */

void test_SubWord_09(void) {
  CU_ASSERT(AES_SubWord(0xcf4f3c09) == 0x8a84eb01);
}

/* From standard, pp. 27 */

void test_RotWord_3c(void) {
  CU_ASSERT(AES_RotWord(0x09cf4f3c) == 0xcf4f3c09);
}

/* From standard, pp. 33 */

void test_AddRoundKey_32(void) {
  AES_byte state_actual[4][4] = {
    {0x32, 0x43, 0xf6, 0xa8},
    {0x88, 0x5a, 0x30, 0x8d},
    {0x31, 0x31, 0x98, 0xa2},
    {0xe0, 0x37, 0x07, 0x34}
  };
  AES_byte state_expected[4][4] = {
    {0x19, 0x3d, 0xe3, 0xbe},
    {0xa0, 0xf4, 0xe2, 0x2b},
    {0x9a, 0xc6, 0x8d, 0x2a},
    {0xe9, 0xf8, 0x48, 0x08}
  };
  AES_word w[] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
  int i, j;
  int passed = 1;
  
  AES_AddRoundKey(state_actual, w);
  for (i = 0; i < 4; i ++) {
    for (j = 0; j < 4; j ++) {
      if (state_actual[j][i] != state_expected[j][i]) {
	passed = 0;
	printf("test_AddRoundKey_32 failed, i=%d, j=%d, actual=%x, expected=%x\n",
	       i, j, state_actual[j][i], state_expected[j][i]);
	CU_FAIL("test_AddRoundKey_32 failed");
      }
    }
  }
  
  if (passed)
    CU_PASS("test_AddRoundKey_32 passed");
  
}

/* From standard, pp. 33 */

void test_SubBytes_19(void) {
  AES_byte state_actual[4][4] = {
    {0x19, 0x3d, 0xe3, 0xbe},
    {0xa0, 0xf4, 0xe2, 0x2b},
    {0x9a, 0xc6, 0x8d, 0x2a},
    {0xe9, 0xf8, 0x48, 0x08}
  };
  AES_byte state_expected[4][4] = {
    {0xd4, 0x27, 0x11, 0xae},
    {0xe0, 0xbf, 0x98, 0xf1},
    {0xb8, 0xb4, 0x5d, 0xe5},
    {0x1e, 0x41, 0x52, 0x30}
  };
  int i, j;
  int passed = 1;
  
  AES_SubBytes(state_actual);
  for (i = 0; i < 4; i ++) {
    for (j = 0; j < 4; j ++) {
      if (state_actual[j][i] != state_expected[j][i]) {
	passed = 0;
	printf("test_SubBytes_19 failed, i=%d, j=%d, actual=%x, expected=%x\n",
	       i, j, state_actual[j][i], state_expected[j][i]);
	CU_FAIL("test_SubBytes_19 failed");
      }
    }
  }
  
  if (passed)
    CU_PASS("test_SubBytes_19 passed");
  
}

/* From standard, pp. 33 */

void test_ShiftRows_d4(void) {
  AES_byte state_actual[4][4] = {
    {0xd4, 0x27, 0x11, 0xae},
    {0xe0, 0xbf, 0x98, 0xf1},
    {0xb8, 0xb4, 0x5d, 0xe5},
    {0x1e, 0x41, 0x52, 0x30}
  };
  AES_byte state_expected[4][4] = {
    {0xd4, 0xbf, 0x5d, 0x30},
    {0xe0, 0xb4, 0x52, 0xae},
    {0xb8, 0x41, 0x11, 0xf1},
    {0x1e, 0x27, 0x98, 0xe5}
  };
  int i, j;
  int passed = 1;
  
  AES_ShiftRows(state_actual);
  for (i = 0; i < 4; i ++) {
    for (j = 0; j < 4; j ++) {
      if (state_actual[j][i] != state_expected[j][i]) {
	passed = 0;
	printf("test_ShiftRows_d4 failed, j=%d, i=%d, actual=%x, expected=%x\n",
	       j, i, state_actual[j][i], state_expected[j][i]);
	CU_FAIL("test_ShiftRows_d4 failed");
      }
    }
  }
  
  if (passed)
    CU_PASS("test_ShiftRows_d4 passed");
  
}

/* From standard, pp. 33 */

void test_MixColumns_d4(void) {
  AES_byte state_actual[4][4] = {
    {0xd4, 0xbf, 0x5d, 0x30},
    {0xe0, 0xb4, 0x52, 0xae},
    {0xb8, 0x41, 0x11, 0xf1},
    {0x1e, 0x27, 0x98, 0xe5}
  };
  AES_byte state_expected[4][4] = {
    {0x04, 0x66, 0x81, 0xe5},
    {0xe0, 0xcb, 0x19, 0x9a},
    {0x48, 0xf8, 0xd3, 0x7a},
    {0x28, 0x06, 0x26, 0x4c}
  };
  int i, j;
  int passed = 1;
  
  AES_MixColumns(state_actual);
  for (i = 0; i < 4; i ++) {
    for (j = 0; j < 4; j ++) {
      if (state_actual[j][i] != state_expected[j][i]) {
	passed = 0;
	printf("test_MixColumns_d4 failed, j=%d, i=%d, actual=%x, expected=%x\n",
	       j, i, state_actual[j][i], state_expected[j][i]);
	CU_FAIL("test_MixColumns_d4 failed");
      }
    }
  }
  
  if (passed)
    CU_PASS("test_MixColumns_d4 passed");
  
}

/* From standard, pp. 35- */

void test_encrypt_00(void) {
  AES_word w[N_W];
  AES_byte plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  AES_byte key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  AES_byte ciphertext_actual[16];
  AES_byte ciphertext_expected[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
  };
  int i;
  int passed = 1;

  AES_KeyExpansion(key, w);
  AES_encrypt(plaintext, ciphertext_actual, w);
  
  for (i = 0; i < 16; i ++) {
    if (ciphertext_actual[i] != ciphertext_expected[i]) {
      passed = 0;
      printf("test_encrypt_00 failed, i=%d, actual=%x, expected=%x\n",
	     i, ciphertext_actual[i], ciphertext_expected[i]);
      CU_FAIL("test_encrypt_00 failed");
    }
  }
  
  if (passed)
    CU_PASS("test_encrypt_00 passed");
  
}

void gradle_cunit_register() {
    CU_pSuite pSuiteRypto = CU_add_suite("rypto tests", suite_init, suite_clean);
    CU_add_test(pSuiteRypto, "test_void", test_void);
    CU_add_test(pSuiteRypto, "test_makeword", test_makeword);
    CU_add_test(pSuiteRypto, "test_SubWord_09", test_SubWord_09);
    CU_add_test(pSuiteRypto, "test_RotWord_3c", test_RotWord_3c);
    CU_add_test(pSuiteRypto, "test_KeyExpansion_00", test_KeyExpansion_00);
    CU_add_test(pSuiteRypto, "test_KeyExpansion_ff", test_KeyExpansion_ff);
    CU_add_test(pSuiteRypto, "test_KeyExpansion_01", test_KeyExpansion_01);
    CU_add_test(pSuiteRypto, "test_AddRoundKey_32", test_AddRoundKey_32);
    CU_add_test(pSuiteRypto, "test_SubBytes_19", test_SubBytes_19);
    CU_add_test(pSuiteRypto, "test_ShiftRows_d4", test_ShiftRows_d4);
    CU_add_test(pSuiteRypto, "test_MixColumns_d4", test_MixColumns_d4);
    CU_add_test(pSuiteRypto, "test_encrypt_00", test_encrypt_00);
}
