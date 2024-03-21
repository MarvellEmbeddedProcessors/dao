/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_ASSERT_H_
#define _DAO_ASSERT_H_

#include <dao_log.h>

/** @file
 *
 * Defining macros for assertions in user test cases.
 */

/** Normal assertion.
 * Reports failure with no other action.
 */
#define DAO_ASSERT(cond, msg, ...)                                                                 \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			dao_err("Test assert %s line %d failed: " msg "\n", __func__, __LINE__,    \
				##__VA_ARGS__);                                                    \
		}                                                                                  \
	} while (0)

/** Fatal assertion
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_FATAL(cond, msg, ...)                                                           \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			dao_exit("Test assert %s line %d failed: " msg "\n", __func__, __LINE__,   \
				 ##__VA_ARGS__);                                                   \
		}                                                                                  \
	} while (0)

/**
 * Asserts that a == b
 */
#define DAO_ASSERT_EQUAL(a, b, msg, ...) DAO_ASSERT((a) == (b), msg, ##__VA_ARGS__)

/**
 * Asserts that a == b
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_EQUAL_FATAL(a, b, msg, ...) DAO_ASSERT_FATAL((a) == (b), msg, ##__VA_ARGS__)

/**
 * Asserts that a != b
 */
#define DAO_ASSERT_NOT_EQUAL(a, b, msg, ...) DAO_ASSERT((a) != (b), msg, ##__VA_ARGS__)

/**
 * Asserts that a != b
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_NOT_EQUAL_FATAL(a, b, msg, ...) DAO_ASSERT_FATAL((a) != (b), msg, ##__VA_ARGS__)

/**
 * Asserts that val == 0
 */
#define DAO_ASSERT_SUCCESS(val, msg, ...) DAO_ASSERT((val) == 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val == 0
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_SUCCESS_FATAL(val, msg, ...) DAO_ASSERT_FATAL((val) == 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val != 0
 */
#define DAO_ASSERT_FAIL(val, msg, ...) DAO_ASSERT((val) != 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val != 0
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_FAIL_FATAL(val, msg, ...) DAO_ASSERT_FATAL((val) != 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val == 0
 */
#define DAO_ASSERT_ZERO(val, msg, ...) DAO_ASSERT((val) == 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val == 0
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_ZERO_FATAL(val, msg, ...) DAO_ASSERT_FATAL((val) == 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val != 0
 */
#define DAO_ASSERT_NOT_ZERO(val, msg, ...) DAO_ASSERT((val) != 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val != 0
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_NOT_ZERO_FATAL(val, msg, ...) DAO_ASSERT_FATAL((val) != 0, msg, ##__VA_ARGS__)

/**
 * Asserts that val == NULL
 */
#define DAO_ASSERT_NULL(val, msg, ...) DAO_ASSERT((val) == NULL, msg, ##__VA_ARGS__)

/**
 * Asserts that val == NULL
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_NULL_FATAL(val, msg, ...) DAO_ASSERT_FATAL((val) == NULL, msg, ##__VA_ARGS__)

/**
 * Asserts that val != NULL
 */
#define DAO_ASSERT_NOT_NULL(val, msg, ...) DAO_ASSERT((val) != NULL, msg, ##__VA_ARGS__)

/**
 * Asserts that val != NULL
 * Reports failure and causes test to abort.
 */
#define DAO_ASSERT_NOT_NULL_FATAL(val, msg, ...) DAO_ASSERT_FATAL((val) != NULL, msg, ##__VA_ARGS__)
#endif /* _DAO_ASSERT_H_ */
