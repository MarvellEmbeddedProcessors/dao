/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#ifndef __LC_TEST_COMP_H__
#define __LC_TEST_COMP_H__

#include "test.h"

extern struct unit_test_suite lc_testsuite_comp;

uint8_t *text_to_bytes_with_null(const char *text, size_t *out_len);
int compdev_testsuite_setup(void);

#endif /* __LC_TEST_COMP_H__ */
