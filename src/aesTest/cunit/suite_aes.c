#include <CUnit/Basic.h>
#include "gradle_cunit_register.h"
/* #include "test_operators.h" */

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

void gradle_cunit_register() {
    CU_pSuite pSuiteRypto = CU_add_suite("rypto tests", suite_init, suite_clean);
    CU_add_test(pSuiteRypto, "test_void", test_void);
    /* CU_add_test(pSuiteRypto, "test_fail", test_fail); */
}
