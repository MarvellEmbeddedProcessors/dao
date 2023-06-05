/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_DYNAMIC_STRING_H_
#define _DAO_DYNAMIC_STRING_H_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * DAO dynamic string APIs helps to construct/store/extend/print variable
 * length strings
 *
 * A "dynamic string", that is, a buffer that can be used to construct a
 * string across a series of operations that extend or modify it.
 *
 * The 'string' member does not always point to a null-terminated string.
 * Initially it is NULL, and even when it is nonnull, some operations do not
 * ensure that it is null-terminated.  Use dao_ds_cstr() to ensure that memory is
 * allocated for the string and that it is null-terminated.
 */

/**
 * DAO dynamic string object: struct dao_ds
 */
struct dao_ds {
	char *string;		/*< Null-terminated string. */
	size_t length;		/*< Bytes used, not including null terminator. */
	size_t allocated;	/*< Bytes allocated, not including null terminator. */
};

#define DS_EMPTY_INITIALIZER { NULL, 0, 0 }

/**
 * Initialize "dynamic string" object
 *
 * @param ds
 *   "dynamic string" object
 */
void dao_ds_init(struct dao_ds *ds);

/**
 * Set length of string, managed by "dynamic string" object, to 0.
 * Does not free memory
 *
 * @param ds
 *   "dynamic string" object
 */
void dao_ds_clear(struct dao_ds *ds);

/**
 * Reduces length of string, managed by "dynamic string" object, to no more
 * than 'new length'. If its length is already 'new_length' or less, does
 * nothing.
 *
 * @param ds
 *   "dynamic string" object
 * @param new_length
 *   Length to which string to be truncated
 */
void dao_ds_truncate(struct dao_ds *ds, size_t new_length);

/**
 * Ensures that at least 'min_length + 1' bytes (including space for a null
 * terminator) are allocated for ds->string, allocating or reallocating memory
 * as necessary.
 *
 * @param ds
 *   "dynamic string" object
 * @param min_length
 *   Length which ds->string should be able to hold at minimum.
 */
void dao_ds_reserve(struct dao_ds *ds, size_t min_length);

/**
 * Appends space for 'n' bytes to the end of 'ds->string', increasing
 * 'ds->length' by the same amount, and returns the first appended byte.  The
 * caller should fill in all 'n' bytes starting at the return value.
 *
 * @param ds
 *   "dynamic string" object
 * @param n
 *   Number of bytes to be appended to the string of ds->string
 *
 * @return
 *  String pointing to first appended byte
 */
char *dao_ds_put_uninit(struct dao_ds *ds, size_t n);

/**
 * Appends unicode code point 'uc' to 'ds' in UTF-8 encoding.
 *
 * @param ds
 *   "dynamic string" object
 * @param uc
 *   unicode code point
 */
void dao_ds_put_utf8(struct dao_ds *ds, int uc);

/**
 * Append single character 'c' multiple times to 'ds'
 *
 * @param ds
 *   "dynamic string" object
 * @param c
 *   character to be added
 * @param n
 *   No. of times character to be added in string
 */
void dao_ds_put_char_multiple(struct dao_ds *ds, char c, size_t n);

/**
 * Append buffer 'buf' of length 'n' to 'ds'
 *
 * @param ds
 *   "dynamic string" object
 * @param buf
 *   buffer to be appended
 * @param n
 *   length of buffer 'buf'
 */
void dao_ds_put_buffer(struct dao_ds *ds, const char *buf, size_t n);

/**
 * Append string 'str' to 'ds'
 *
 * @param ds
 *   "dynamic string" object
 * @param str
 *   string to be appended
 */
void dao_ds_put_cstr(struct dao_ds *ds, const char *str);

/**
 * Append string 'str' to 'ds' and free 'str' afterwards
 *
 * @param ds
 *   "dynamic string" object
 * @param str
 *   After appending 'str' to ds, memory associated with 'str' is freed
 */
void dao_ds_put_and_free_cstr(struct dao_ds *ds, char *str);

/**
 * Append 'format' string to 'ds' with variable arguments. Functionality
 * similar to sprintf()
 *
 * @param ds
 *   "dynamic string" object
 * @param format
 *   string with variable arguments
 */
void dao_ds_put_format(struct dao_ds *ds, const char *format, ...);

/**
 * Append 'format' string to 'ds' with variable arguments and va_list
 *
 * @param ds
 *   "dynamic string" object
 * @param format
 *   string with variable arguments
 * @param va
 *   va_list
 */
void dao_ds_put_format_valist(struct dao_ds *ds, const char *format, va_list va);

/**
 * Append buffer 'buf' of 'size' bytes to 'ds' and convert each character in
 * printable format. In other words, print ascii characters in range of [@,A-Z,
 * a-z,\,^.`,~,_,{,},|,]
 *
 * @param ds
 *   "dynamic string" object
 * @param buf
 *   buffer to be appended
 * @param size
 *   size of buffer 'buf' in bytes
 */
void dao_ds_put_printable(struct dao_ds *ds, const char *buf, size_t size);

/**
 * Append buffer 'buf' of 'size' bytes to 'ds' and convert each character in
 * hexadecimal format.
 *
 * @param ds
 *   "dynamic string" object
 * @param buf
 *   buffer to be appended
 * @param size
 *   size of buffer 'buf' in bytes
 */
void dao_ds_put_hex(struct dao_ds *ds, const void *buf, size_t size);

/**
 * Writes the 'size' bytes in 'buf' to 'string' as hex bytes arranged 16 per
 * line.  Numeric offsets are also included, starting at 'ofs' for the first
 * byte in 'buf'.  If 'ascii' is true then the corresponding ASCII characters
 * are also rendered alongside.
 *
 * @param ds
 *   "dynamic string" object
 * @param buf
 *   buffer to be appended
 * @param size
 *   size of buffer 'buf' in bytes
 * @param ofs
 *   offset to start with
 * @param ascii
 *   if 'true' then ASCII characters are also rendered alongside hex
 */
void dao_ds_put_hex_dump(struct dao_ds *ds, const void *buf, size_t size,
			 uintptr_t ofs, bool ascii);

/**
 * Same as 'dao_ds_put_hex_dump', but doesn't print lines that only contains
 * zero bytes.
 *
 * @param ds
 *   "dynamic string" object
 * @param buf
 *   buffer to be appended
 * @param size
 *   size of buffer 'buf' in bytes
 * @param ofs
 *   offset to start with
 * @param ascii
 *   if 'true' then ASCII characters are also rendered alongside hex
 */
void dao_ds_put_sparse_hex_dump(struct dao_ds *ds, const void *buf, size_t size,
				uintptr_t ofs, bool ascii);
/**
 * Get line from 'file' until encounter '\n' or 'EOF' and save it to 'ds'
 *
 * @param ds
 *   "dynamic string" object to which a line is written
 * @param file
 *   File from where a line is read
 *
 * @return
 * 0: On Success
 * EOF: On Failure
 */
int dao_ds_get_line(struct dao_ds *ds, FILE *file);

/**
 * Reads a line from 'file' into 'ds', clearing anything initially in 'ds'.
 * Deletes comments introduced by "#" and skips lines that contains only white
 * space (after deleting comments).
 *
 * If 'line_numberp' is nonnull, increments '*line_numberp' by the number of
 * lines read from 'file'.
 *
 * @param ds
 *   "dynamic string" object
 * @param file
 *   File pointer
 * @param[out] line_numberp
 *  If nonnull, returns number of lines read
 *
 * @return
 * 0: On Success
 * EOF: if non-blank line was found
 */
int dao_ds_get_preprocessed_line(struct dao_ds *ds, FILE *file, int *line_numberp);

/**
 * Reads a line from 'file' into 'ds' and does some preprocessing on it:
 *
 * - If the line begins with #, prints it on stdout and reads the next line.
 *
 * - Otherwise, if the line contains an # somewhere else, strips it and
 *   everything following it (as a comment).
 *
 * - If (after comment removal) the line contains only white space, prints
 *   a blank line on stdout and reads the next line.
 *
 * - Otherwise, returns the line to the caller.
 *
 * This is useful in some of the tests, where we want to check that parsing
 * and then re-formatting some kind of data does not change it, but we also
 * want to be able to put comments in the input.
 *
 * @param ds
 *   "dynamic string" object
 * @param file
 *   File pointer
 *
 * @return
 *  0: If Success,
 *  EOF: Non-blank line
 * Returns 0 if successful, EOF if no non-blank line was found.
 */
int dao_ds_get_test_line(struct dao_ds *ds, FILE *file);

/**
 * Return string corresponding to ds. strxxx()/printf() operations are valid on
 * returned string
 *
 * @param ds
 *   "dynamic object"
 *
 * @return
 * On success: valid string
 * On failure: NULL string
 */
char *dao_ds_cstr(struct dao_ds *ds);

/**
 * Returns a null-terminated string representing the current contents of 'ds',
 * which the caller is expected to free with free(), then clears the contents
 * of 'ds'.
 *
 * @param ds
 *  "dynamic string object
 *
 * @return
 * On success: null-terminated string
 */
char *dao_ds_steal_cstr(struct dao_ds *ds);

/**
 * Free string associated with 'ds'
 *
 * @param ds
 *   "dynamic string" object
 */
void dao_ds_destroy(struct dao_ds *ds);

/**
 * Swaps the content of 'a' and 'b'.
 *
 * @param a
 *  First string to be swapped with string 'b'
 * @param b
 *  Second string to be swapped with string 'a'
 */
void dao_ds_swap(struct dao_ds *a, struct dao_ds *b);

/**
 * Return last character in string associated by ds
 *
 * @param ds
 *   "dynamic string object
 *
 * @return
 * On Success: last character as integer
 * On Failure: EOF
 */
int dao_ds_last(const struct dao_ds *ds);

/**
 * Chomp character 'c' if it is last character in ds->string and return true
 * otherwise return false
 *
 * @param ds
 *   "dynamic string" object
 * @param c
 *   character to be chomped from last character of string
 *
 * @return
 * True: if character provided is successfully chompped from last character of
 * string
 * False: If 'c' is not chompped
 */
bool dao_ds_chomp(struct dao_ds *ds, int c);

/**
 * Clone string 'source' into string 'dst'
 *
 * @param source
 *  "dynamic string" to be cloned
 * @param dst
 *  destination "dynamic string" cloned from source on return
 */
void dao_ds_clone(struct dao_ds *dst, struct dao_ds *source);

void dao_ds_put_char__(struct dao_ds *ds, char c);

/* Inline functions. */
/**
 * Add  character  to dynamic string
 *
 * @param ds
 *  "dynamic sting" object
 * @param c
 *  character to be added in ds->string
 */
static inline void
dao_ds_put_char(struct dao_ds *ds, char c)
{
	if (ds->length < ds->allocated) {
		ds->string[ds->length++] = c;
		ds->string[ds->length] = '\0';
	} else {
		dao_ds_put_char__(ds, c);
	}
}

#ifdef __cplusplus
}
#endif

#endif /* dao_dynamic_string.h */
