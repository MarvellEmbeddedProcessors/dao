/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <dao_log.h>
#include <dao_util.h>

#define HW_PF_SHIFT  10
#define HW_PF_MASK   0x3F
#define HW_FUNC_MASK 0x3FF

typedef struct pci_addr {
	/** PCI Domain */
	uint32_t domain;
	/** PCI Bus number */
	uint8_t bus;
	/** PCI Device number */
	uint8_t devid;
	/** PCI Function number */
	uint8_t function;
} pci_addr_t;

static int
oct_to_dec(int n)
{
	int dec_value = 0;
	int last_digit;
	int temp = n;
	int base = 1;

	while (temp) {
		last_digit = temp % 10;
		temp = temp / 10;
		dec_value += last_digit * base;
		base = base * 8;
	}

	return dec_value;
}

static inline const char *
pciadd_field_u8_get(const char *in, void *_u8, char dlm)
{
	unsigned long val;
	uint8_t *u8 = _u8;
	char *end;

	/* empty string is an error though strtoul() returns 0 */
	if (*in == '\0')
		return NULL;

	errno = 0;
	val = strtoul(in, &end, 16);
	if (errno != 0 || end[0] != dlm || val > UINT8_MAX) {
		errno = errno ? errno : EINVAL;
		return NULL;
	}
	*u8 = (uint8_t)val;
	return end + 1;
}

static int
pci_dbdf_parse(const char *pci_bdf, pci_addr_t *dev_addr)
{
	const char *in = pci_bdf;
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(in, &end, 16);
	if (errno != 0 || end[0] != ':' || val > UINT16_MAX)
		return -EINVAL;
	dev_addr->domain = (uint16_t)val;
	in = end + 1;
	in = pciadd_field_u8_get(in, &dev_addr->bus, ':');
	if (in == NULL)
		return -EINVAL;
	in = pciadd_field_u8_get(in, &dev_addr->devid, '.');
	if (in == NULL)
		return -EINVAL;
	in = pciadd_field_u8_get(in, &dev_addr->function, '\0');
	if (in == NULL)
		return -EINVAL;
	return 0;
}

int
dao_pci_bdf_to_hw_func(const char *pci_bdf)
{
	uint16_t pf, func;
	pci_addr_t addr;
	int rc = 0;

	rc = pci_dbdf_parse(pci_bdf, &addr);
	if (rc < 0) {
		dao_err("Failed to parse PCI dev string, err %d", rc);
		goto fail;
	}

	pf = addr.bus;
	func = (uint16_t)oct_to_dec((addr.devid * 10) + addr.function);

	rc = (pf - 1) << HW_PF_SHIFT | func;
fail:
	return rc;
}
