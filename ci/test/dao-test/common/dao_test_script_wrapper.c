/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stdio.h>

int main(int argc, char *argv[])
{
	if (argc > 1)
		printf("Skipping test %s\n", argv[1]);

	return 77;
}
