/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_dynamic_string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dao_util.h>

/** Returns true if the 'n' bytes starting at 'p' are 'byte'. */
static inline int
is_all_byte(const void *p_, size_t n, uint8_t byte)
{
	const uint8_t *p = p_;
	size_t i;

	for (i = 0; i < n; i++) {
		if (p[i] != byte)
			return 0;
	}
	return 1;
}

/** Returns true if the 'n' bytes starting at 'p' are zeros. */
static inline int
is_all_zeros(const void *p, size_t n)
{
	return is_all_byte(p, n, 0);
}

/** Initializes 'ds' as an empty string buffer. */
void
dao_ds_init(struct dao_ds *ds)
{
	ds->string = NULL;
	ds->length = 0;
	ds->allocated = 0;
}

/**
 * Sets 'ds''s length to 0, effectively clearing any existing content.  Does
 * not free any memory.
 */
void
dao_ds_clear(struct dao_ds *ds)
{
	ds->length = 0;
}

/**
 * Reduces 'ds''s length to no more than 'new_length'.  (If its length is
 * already 'new_length' or less, does nothing.)
 */
void
dao_ds_truncate(struct dao_ds *ds, size_t new_length)
{
	if (ds->length > new_length) {
		ds->length = new_length;
		ds->string[new_length] = '\0';
	}
}

/**
 * Ensures that at least 'min_length + 1' bytes (including space for a null
 * terminator) are allocated for ds->string, allocating or reallocating memory
 * as necessary.
 */
void
dao_ds_reserve(struct dao_ds *ds, size_t min_length)
{
	if (min_length > ds->allocated || !ds->string) {
		ds->allocated += RTE_MAX(min_length, ds->allocated);
		ds->allocated = RTE_MAX((size_t)8, ds->allocated);
		ds->string = realloc(ds->string, ds->allocated + 1);
	}
}

/** Appends space for 'n' bytes to the end of 'ds->string', increasing
 * 'ds->length' by the same amount, and returns the first appended byte.  The
 * caller should fill in all 'n' bytes starting at the return value.
 */
char *
dao_ds_put_uninit(struct dao_ds *ds, size_t n)
{
	dao_ds_reserve(ds, ds->length + n);
	ds->length += n;
	ds->string[ds->length] = '\0';
	return &ds->string[ds->length - n];
}

void
dao_ds_put_char__(struct dao_ds *ds, char c)
{
	*dao_ds_put_uninit(ds, 1) = c;
}

/** Appends unicode code point 'uc' to 'ds' in UTF-8 encoding. */
void
dao_ds_put_utf8(struct dao_ds *ds, int uc)
{
	if (uc <= 0x7f) {
		dao_ds_put_char(ds, uc);
	} else if (uc <= 0x7ff) {
		dao_ds_put_char(ds, 0xc0 | (uc >> 6));
		dao_ds_put_char(ds, 0x80 | (uc & 0x3f));
	} else if (uc <= 0xffff) {
		dao_ds_put_char(ds, 0xe0 | (uc >> 12));
		dao_ds_put_char(ds, 0x80 | ((uc >> 6) & 0x3f));
		dao_ds_put_char(ds, 0x80 | (uc & 0x3f));
	} else if (uc <= 0x10ffff) {
		dao_ds_put_char(ds, 0xf0 | (uc >> 18));
		dao_ds_put_char(ds, 0x80 | ((uc >> 12) & 0x3f));
		dao_ds_put_char(ds, 0x80 | ((uc >> 6) & 0x3f));
		dao_ds_put_char(ds, 0x80 | (uc & 0x3f));
	} else {
		/* Invalid code point.  Insert the Unicode general substitute
		 * REPLACEMENT CHARACTER. */
		dao_ds_put_utf8(ds, 0xfffd);
	}
}

void
dao_ds_put_char_multiple(struct dao_ds *ds, char c, size_t n)
{
	memset(dao_ds_put_uninit(ds, n), c, n);
}

void
dao_ds_put_buffer(struct dao_ds *ds, const char *s, size_t n)
{
	memcpy(dao_ds_put_uninit(ds, n), s, n);
}

void
dao_ds_put_cstr(struct dao_ds *ds, const char *s)
{
	size_t s_len = strlen(s);

	memcpy(dao_ds_put_uninit(ds, s_len), s, s_len);
}

void
dao_ds_put_and_free_cstr(struct dao_ds *ds, char *s)
{
	dao_ds_put_cstr(ds, s);
	free(s);
}

void
dao_ds_put_format(struct dao_ds *ds, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	dao_ds_put_format_valist(ds, format, args);
	va_end(args);
}

void
dao_ds_put_format_valist(struct dao_ds *ds, const char *format, va_list args_)
{
	va_list args;
	size_t available;
	size_t needed;

	va_copy(args, args_);
	available = ds->string ? ds->allocated - ds->length + 1 : 0;
	needed = vsnprintf(ds->string
						? &ds->string[ds->length]
						: NULL,
						available, format, args);
	va_end(args);

	if (needed < available) {
		ds->length += needed;
	} else {
		dao_ds_reserve(ds, ds->length + needed);

		va_copy(args, args_);
		available = ds->allocated - ds->length + 1;
		needed = vsnprintf(&ds->string[ds->length],
				   available, format, args);
		va_end(args);

		assert(needed < available);
		ds->length += needed;
	}
}

void
dao_ds_put_printable(struct dao_ds *ds, const char *s, size_t n)
{
	dao_ds_reserve(ds, ds->length + n);
	while (n-- > 0) {
		unsigned char c = *s++;

		if (c < 0x20 || c > 0x7e || c == '\\' || c == '"')
			dao_ds_put_format(ds, "\\%03o", (int)c);
		else
			dao_ds_put_char(ds, c);
	}
}

int
dao_ds_get_line(struct dao_ds *ds, FILE *file)
{
	dao_ds_clear(ds);
	for (;;) {
		int c = getc(file);

		if (c == EOF)
			return ds->length ? 0 : EOF;
		else if (c == '\n')
			return 0;
		else
			dao_ds_put_char(ds, c);
	}
}

/**
 * Reads a line from 'file' into 'ds', clearing anything initially in 'ds'.
 * Deletes comments introduced by "#" and skips lines that contains only white
 * space (after deleting comments).
 *
 * If 'line_numberp' is nonnull, increments '*line_numberp' by the number of
 * lines read from 'file'.
 *
 * Returns 0 if successful, EOF if no non-blank line was found.
 */
int
dao_ds_get_preprocessed_line(struct dao_ds *ds, FILE *file, int *line_numberp)
{
	while (!dao_ds_get_line(ds, file)) {
		char *line = dao_ds_cstr(ds);
		char *comment;

		if (line_numberp)
			++*line_numberp;

		/* Delete comments. */
		comment = strchr(line, '#');
		if (comment)
			*comment = '\0';

		/* Return successfully unless the line is all spaces. */
		if (line[strspn(line, " \t\n")] != '\0')
			return 0;
	}
	return EOF;
}

/** Reads a line from 'file' into 'ds' and does some preprocessing on it:
 *
 * If the line begins with #, prints it on stdout and reads the next line.
 *
 * Otherwise, if the line contains an # somewhere else, strips it and
 * everything following it (as a comment).
 *
 * If (after comment removal) the line contains only white space, prints
 * a blank line on stdout and reads the next line.
 *
 * Otherwise, returns the line to the caller.
 *
 * This is useful in some of the tests, where we want to check that parsing
 * and then re-formatting some kind of data does not change it, but we also
 * want to be able to put comments in the input.
 *
 * Returns 0 if successful, EOF if no non-blank line was found.
 */
int
dao_ds_get_test_line(struct dao_ds *ds, FILE *file)
{
	for (;;) {
		char *s, *comment;
		int retval;

		retval = dao_ds_get_line(ds, file);
		if (retval)
			return retval;

		s = dao_ds_cstr(ds);
		if (*s == '#') {
			puts(s);
			continue;
		}

		comment = strchr(s, '#');
		if (comment)
			*comment = '\0';

		if (s[strspn(s, " \t\n")] == '\0') {
			putchar('\n');
			continue;
		}

		return 0;
	}
}

char *
dao_ds_cstr(struct dao_ds *ds)
{
	if (!ds->string)
		dao_ds_reserve(ds, 0);
	ds->string[ds->length] = '\0';
	return ds->string;
}

/** Returns a null-terminated string representing the current contents of 'ds',
 * which the caller is expected to free with free(), then clears the contents
 * of 'ds'.
 */
char *
dao_ds_steal_cstr(struct dao_ds *ds)
{
	char *s = dao_ds_cstr(ds);

	dao_ds_init(ds);
	return s;
}

void
dao_ds_destroy(struct dao_ds *ds)
{
	free(ds->string);
}

/** Swaps the content of 'a' and 'b'. */
void
dao_ds_swap(struct dao_ds *a, struct dao_ds *b)
{
	struct dao_ds temp = *a;
	*a = *b;
	*b = temp;
}

void
dao_ds_put_hex(struct dao_ds *ds, const void *buf_, size_t size)
{
	const uint8_t *buf = buf_;
	bool printed = false;
	size_t i;

	for (i = 0; i < size; i++) {
		uint8_t val = buf[i];

		if (val || printed) {
			if (!printed)
				dao_ds_put_format(ds, "0x%" PRIx8, val);
			else
				dao_ds_put_format(ds, "%02" PRIx8, val);
			printed = true;
		}
	}
	if (!printed)
		dao_ds_put_char(ds, '0');
}

static void
dao_ds_put_hex_dump__(struct dao_ds *ds, const void *buf_, size_t size,
		      uintptr_t ofs, bool ascii, bool skip_zero_lines)
{
	const uint8_t *buf = buf_;
	const size_t per_line = 16; /* Maximum bytes per line. */

	while (size > 0) {
		size_t start, end, n;
		size_t i;

		/* Number of bytes on this line. */
		start = ofs % per_line;
		end = per_line;
		if (end - start > size)
			end = start + size;
		n = end - start;

		if (skip_zero_lines && is_all_zeros(&buf[start], n))
			goto next;

		/* Print line. */
		dao_ds_put_format(ds, "%08" PRIxMAX "  ",
				  (uintmax_t)DAO_ROUNDDOWN(ofs, per_line));
		for (i = 0; i < start; i++)
			dao_ds_put_format(ds, "   ");

		for (; i < end; i++)
			dao_ds_put_format(ds, "%02x%c",
					  buf[i - start], i == per_line / 2 - 1 ? '-' : ' ');
		if (ascii) {
			for (; i < per_line; i++)
				dao_ds_put_format(ds, "   ");
			dao_ds_put_format(ds, "|");
			for (i = 0; i < start; i++)
				dao_ds_put_format(ds, " ");
			for (; i < end; i++) {
				int c = buf[i - start];

				dao_ds_put_char(ds, c >= 32 && c < 127 ? c : '.');
			}
			for (; i < per_line; i++)
				dao_ds_put_format(ds, " ");
			dao_ds_put_format(ds, "|");
		} else {
			dao_ds_chomp(ds, ' ');
		}
		dao_ds_put_format(ds, "\n");
next:
		ofs += n;
		buf += n;
		size -= n;
	}
}

/** Writes the 'size' bytes in 'buf' to 'string' as hex bytes arranged 16 per
 * line.  Numeric offsets are also included, starting at 'ofs' for the first
 * byte in 'buf'.  If 'ascii' is true then the corresponding ASCII characters
 * are also rendered alongside.
 */
void
dao_ds_put_hex_dump(struct dao_ds *ds, const void *buf_, size_t size,
		    uintptr_t ofs, bool ascii)
{
	dao_ds_put_hex_dump__(ds, buf_, size, ofs, ascii, false);
}

/** Same as 'dao_ds_put_hex_dump', but doesn't print lines that only contains
 * zero bytes.
 */
void
dao_ds_put_sparse_hex_dump(struct dao_ds *ds, const void *buf_, size_t size,
			   uintptr_t ofs, bool ascii)
{
	dao_ds_put_hex_dump__(ds, buf_, size, ofs, ascii, true);
}

int
dao_ds_last(const struct dao_ds *ds)
{
	return ds->length > 0 ? (unsigned char)ds->string[ds->length - 1] : EOF;
}

bool
dao_ds_chomp(struct dao_ds *ds, int c)
{
	if (ds->length > 0 && ds->string[ds->length - 1] == (char)c) {
		ds->string[--ds->length] = '\0';
		return true;
	} else {
		return false;
	}
}

void
dao_ds_clone(struct dao_ds *dst, struct dao_ds *source)
{
	if (!source->allocated) {
		dao_ds_init(dst);
		return;
	}
	dst->length = source->length;
	dst->allocated = dst->length;
	dst->string = malloc(dst->allocated + 1);
	if (dst->string)
		memcpy(dst->string, source->string, dst->allocated + 1);
}
