/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stddef.h>
#include <stdint.h>

#include <rte_bitmap.h>
#include <rte_flow.h>
#include <rte_malloc.h>

#include <dao_log.h>

#include "flow_parser_priv.h"

#define PARSER_PRIV_FLAGS_DEFAULT    BIT_ULL(0)
#define PARSER_PRIV_FLAGS_EDSA       BIT_ULL(1)
#define PARSER_PRIV_FLAGS_HIGIG      BIT_ULL(2)
#define PARSER_PRIV_FLAGS_LEN_90B    BIT_ULL(3)
#define PARSER_PRIV_FLAGS_EXDSA      BIT_ULL(4)
#define PARSER_PRIV_FLAGS_VLAN_EXDSA BIT_ULL(5)
#define PARSER_PRIV_FLAGS_PRE_L2     BIT_ULL(6)
#define PARSER_PRIV_FLAGS_CUSTOM     BIT_ULL(63)

static int
supp_key_len(uint32_t supp_mask)
{
	int nib_count = 0;

	while (supp_mask) {
		nib_count++;
		supp_mask &= (supp_mask - 1);
	}
	return nib_count * 4;
}

#define BYTESM1_SHIFT 16
#define HDR_OFF_SHIFT 8
static void
update_kex_info(struct profile_xtract_info *xtract_info, uint64_t val)
{
	xtract_info->use_hash = ((val >> 20) & 0x1);
	xtract_info->len = ((val >> BYTESM1_SHIFT) & 0xf) + 1;
	xtract_info->hdr_off = (val >> HDR_OFF_SHIFT) & 0xff;
	xtract_info->key_off = val & 0x3f;
	xtract_info->enable = ((val >> 7) & 0x1);
	xtract_info->flags_enable = ((val >> 6) & 0x1);
}

static void
process_profile_cfg(struct flow_parser *parser, struct profile_cfg_rsp *kex_rsp)
{
	volatile uint64_t(*q)[PROFILE_MAX_INTF][PROFILE_MAX_LID][PROFILE_MAX_LT][PROFILE_MAX_LD];
	struct profile_xtract_info *x_info = NULL;
	int lid, lt, ld, fl, ix;
	profile_dxcfg_t *p;
	uint64_t keyw;
	uint64_t val;

	parser->keyx_supp_nmask[PROFILE_CAM_RX] = kex_rsp->rx_keyx_cfg & 0x7fffffffULL;
	parser->keyx_supp_nmask[PROFILE_CAM_TX] = kex_rsp->tx_keyx_cfg & 0x7fffffffULL;
	parser->keyx_len[PROFILE_CAM_RX] = supp_key_len(parser->keyx_supp_nmask[PROFILE_CAM_RX]);
	parser->keyx_len[PROFILE_CAM_TX] = supp_key_len(parser->keyx_supp_nmask[PROFILE_CAM_TX]);

	keyw = (kex_rsp->rx_keyx_cfg >> 32) & 0x7ULL;
	parser->keyw[PROFILE_CAM_RX] = keyw;
	keyw = (kex_rsp->tx_keyx_cfg >> 32) & 0x7ULL;
	parser->keyw[PROFILE_CAM_TX] = keyw;

	/* Update KEX_LD_FLAG */
	for (ix = 0; ix < PROFILE_MAX_INTF; ix++) {
		for (ld = 0; ld < PROFILE_MAX_LD; ld++) {
			for (fl = 0; fl < PROFILE_MAX_LFL; fl++) {
				x_info = &parser->prx_fxcfg[ix][ld][fl].xtract[0];
				val = kex_rsp->intf_ld_flags[ix][ld][fl];
				update_kex_info(x_info, val);
			}
		}
	}

	/* Update LID, LT and LDATA cfg */
	p = &parser->prx_dxcfg;
	q = (volatile uint64_t(*)[][PROFILE_MAX_LID][PROFILE_MAX_LT][PROFILE_MAX_LD])(
		&kex_rsp->intf_lid_lt_ld);
	for (ix = 0; ix < PROFILE_MAX_INTF; ix++) {
		for (lid = 0; lid < PROFILE_MAX_LID; lid++) {
			for (lt = 0; lt < PROFILE_MAX_LT; lt++) {
				for (ld = 0; ld < PROFILE_MAX_LD; ld++) {
					x_info = &(*p)[ix][lid][lt].xtract[ld];
					val = (*q)[ix][lid][lt][ld];
					update_kex_info(x_info, val);
				}
			}
		}
	}
	/* Update LDATA Flags cfg */
	parser->prx_lfcfg[0].i = kex_rsp->kex_ld_flags[0];
	parser->prx_lfcfg[1].i = kex_rsp->kex_ld_flags[1];
}

#define NIX_CHAN_CPT_CH_END         (0x4ffull) /* [CN10K, .) */
#define NIX_CHAN_CPT_CH_START       (0x800ull) /* [CN10K, .) */
#define NIX_RX_ACTIONOP_UCAST_IPSEC (0x2ull)
#define NIX_CHAN_CPT_X2P_MASK       (0x3ffull)

static void
set_vlan_ltype(struct parse_state *pst)
{
	uint64_t val, mask;
	uint8_t lb_offset;

	lb_offset = rte_popcount32(pst->parser->keyx_supp_nmask[pst->nix_intf] &
				   ((1ULL << PROFILE_LTYPE_LB_OFFSET) - 1));
	lb_offset *= 4;

	mask = ~((0xfULL << lb_offset));
	pst->flow->parsed_data[0] &= mask;
	pst->flow->parsed_data_mask[0] &= mask;
	/* PROFILE_LT_LB_CTAG: 0b0010, PROFILE_LT_LB_STAG_QINQ: 0b0011
	 * Set LB layertype/mask as 0b0010/0b1110 to match both.
	 */
	val = ((uint64_t)(PROFILE_LT_LB_CTAG & PROFILE_LT_LB_STAG_QINQ)) << lb_offset;
	pst->flow->parsed_data[0] |= val;
	pst->flow->parsed_data_mask[0] |= (0xeULL << lb_offset);
}

static void
set_ipv6ext_ltype_mask(struct parse_state *pst)
{
	uint8_t lc_offset, lcflag_offset;
	uint64_t val, mask;

	lc_offset = rte_popcount32(pst->parser->keyx_supp_nmask[pst->nix_intf] &
				   ((1ULL << PROFILE_LTYPE_LC_OFFSET) - 1));
	lc_offset *= 4;

	mask = ~((0xfULL << lc_offset));
	pst->flow->parsed_data[0] &= mask;
	pst->flow->parsed_data_mask[0] &= mask;
	/* PROFILE_LT_LC_IP6: 0b0100, PROFILE_LT_LC_IP6_EXT: 0b0101
	 * Set LC layertype/mask as 0b0100/0b1110 to match both.
	 */
	val = ((uint64_t)(PROFILE_LT_LC_IP6 & PROFILE_LT_LC_IP6_EXT)) << lc_offset;
	pst->flow->parsed_data[0] |= val;
	pst->flow->parsed_data_mask[0] |= (0xeULL << lc_offset);

	/* If LC LFLAG is non-zero, set the LC LFLAG mask to 0xF. In general
	 * case flag mask is set same as the value in data. For example, to
	 * match 3 VLANs, flags have to match a range of values. But, for IPv6
	 * extended attributes matching, we need an exact match. Hence, set the
	 * mask as 0xF. This is done only if LC LFLAG value is non-zero,
	 * because for AH and ESP, LC LFLAG is zero and we don't want to match
	 * zero in LFLAG.
	 */
	if (pst->parser->keyx_supp_nmask[pst->nix_intf] & (1ULL << PROFILE_LFLAG_LC_OFFSET)) {
		lcflag_offset = rte_popcount32(pst->parser->keyx_supp_nmask[pst->nix_intf] &
					       ((1ULL << PROFILE_LFLAG_LC_OFFSET) - 1));
		lcflag_offset *= 4;

		mask = (0xfULL << lcflag_offset);
		val = pst->flow->parsed_data[0] & mask;
		if (val)
			pst->flow->parsed_data_mask[0] |= mask;
	}
}

static int
populate_parsed_data(struct flow_parser *parser, struct parse_state *pst, bool tcam_alloc)
{
	/* This is non-LDATA part in search key */
	uint64_t key_data[2] = {0ULL, 0ULL};
	uint64_t key_mask[2] = {0ULL, 0ULL};
	int key_len, bit = 0, index;
	int intf = pst->flow->nix_intf;
	int off, idx, data_off = 0;
	uint8_t lid, mask, data;
	uint16_t layer_info;
	uint64_t lt, flags;

	RTE_SET_USED(tcam_alloc);

	/* Skip till Layer A data start */
	while (bit < PROFILE_KEX_S_LA_OFFSET) {
		if (parser->keyx_supp_nmask[intf] & (1 << bit))
			data_off++;
		bit++;
	}

	/* Each bit represents 1 nibble */
	data_off *= 4;

	index = 0;
	for (lid = 0; lid < PROFILE_MAX_LID; lid++) {
		/* Offset in key */
		off = PROFILE_KEX_S_LID_OFFSET(lid);
		lt = pst->lt[lid] & 0xf;
		flags = pst->flags[lid] & 0xff;

		/* PROFILE_LAYER_KEX_S */
		layer_info = ((parser->keyx_supp_nmask[intf] >> off) & 0x7);

		if (layer_info) {
			for (idx = 0; idx <= 2; idx++) {
				if (layer_info & (1 << idx)) {
					if (idx == 2) {
						data = lt;
						mask = 0xf;
					} else if (idx == 1) {
						data = ((flags >> 4) & 0xf);
						mask = ((flags >> 4) & 0xf);
					} else {
						data = (flags & 0xf);
						mask = (flags & 0xf);
					}

					if (data_off >= 64) {
						data_off = 0;
						index++;
					}
					key_data[index] |= ((uint64_t)data << data_off);

					if (lt == 0)
						mask = 0;
					key_mask[index] |= ((uint64_t)mask << data_off);
					data_off += 4;
				}
			}
		}
	}

	/* Copy this into mcam string */
	key_len = (pst->parser->keyx_len[intf] + 7) / 8;
	memcpy(pst->flow->parsed_data, key_data, key_len);
	memcpy(pst->flow->parsed_data_mask, key_mask, key_len);

	if (pst->set_vlan_ltype_mask)
		set_vlan_ltype(pst);

	if (pst->set_ipv6ext_ltype_mask)
		set_ipv6ext_ltype_mask(pst);

	/*
	 * Now we have mcam data and mask formatted as
	 * [Key_len/4 nibbles][0 or 1 nibble hole][data]
	 * hole is present if key_len is odd number of nibbles.
	 * mcam data must be split into 64 bits + 48 bits segments
	 * for each back W0, W1.
	 */

	return 0;
}

static void
prep_tcam_ldata(uint8_t *ptr, const uint8_t *data, int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		ptr[idx] = data[len - 1 - idx];
}

static int
check_copysz(size_t size, size_t len)
{
	if (len <= size)
		return len;
	return PARSE_ERR_PARAM;
}

static inline int
mem_is_zero(const void *mem, int len)
{
	const char *m = mem;
	int i;

	for (i = 0; i < len; i++) {
		if (m[i] != 0)
			return 0;
	}
	return 1;
}

static void
set_hw_mask(struct parse_item_info *info, struct profile_xtract_info *xinfo, char *hw_mask)
{
	int max_off, offset;
	int j;

	if (xinfo->enable == 0)
		return;

	if (xinfo->hdr_off < info->hw_hdr_len)
		return;

	max_off = xinfo->hdr_off + xinfo->len - info->hw_hdr_len;

	if (max_off > info->len)
		max_off = info->len;

	offset = xinfo->hdr_off - info->hw_hdr_len;
	for (j = offset; j < max_off; j++)
		hw_mask[j] = 0xff;
}

static void
hw_supp_mask(struct parse_state *pst, struct parse_item_info *info, int lid, int lt)
{
	struct profile_xtract_info *xinfo, *lfinfo;
	char *hw_mask = info->hw_mask;
	int lf_cfg = 0;
	int i, j;
	int intf;

	intf = pst->nix_intf;
	xinfo = pst->parser->prx_dxcfg[intf][lid][lt].xtract;
	memset(hw_mask, 0, info->len);

	for (i = 0; i < PROFILE_MAX_LD; i++)
		set_hw_mask(info, &xinfo[i], hw_mask);

	for (i = 0; i < PROFILE_MAX_LD; i++) {
		if (xinfo[i].flags_enable == 0)
			continue;

		lf_cfg = pst->parser->prx_lfcfg[i].i;
		if (lf_cfg == lid) {
			for (j = 0; j < PROFILE_MAX_LFL; j++) {
				lfinfo = pst->parser->prx_fxcfg[intf][i][j].xtract;
				set_hw_mask(info, &lfinfo[0], hw_mask);
			}
		}
	}
}

static inline int
mask_is_supported(const char *mask, const char *hw_mask, int len)
{
	/*
	 * If no hw_mask, assume nothing is supported.
	 * mask is never NULL
	 */
	if (hw_mask == NULL)
		return mem_is_zero(mask, len);

	while (len--) {
		if ((mask[len] | hw_mask[len]) != hw_mask[len])
			return 0; /* False */
	}
	return 1;
}

static int
parse_item_basic(const struct rte_flow_item *item, struct parse_item_info *info)
{
	/* Item must not be NULL */
	if (item == NULL)
		return PARSE_ERR_PARAM;

	/* Don't support ranges */
	if (item->last != NULL)
		return PARSE_ERR_INVALID_RANGE;

	/* If spec is NULL, both mask and last must be NULL, this
	 * makes it to match ANY value (eq to mask = 0).
	 * Setting either mask or last without spec is an error
	 */
	if (item->spec == NULL) {
		if (item->last == NULL && item->mask == NULL) {
			info->spec = NULL;
			return 0;
		}
		return PARSE_ERR_INVALID_SPEC;
	}

	/* We have valid spec */
	if (item->type != RTE_FLOW_ITEM_TYPE_RAW)
		info->spec = item->spec;

	/* If mask is not set, use default mask, err if default mask is
	 * also NULL.
	 */
	if (item->mask == NULL) {
		if (info->def_mask == NULL)
			return PARSE_ERR_PARAM;
		info->mask = info->def_mask;
	} else {
		if (item->type != RTE_FLOW_ITEM_TYPE_RAW)
			info->mask = item->mask;
	}

	if (info->mask == NULL)
		return PARSE_ERR_INVALID_MASK;

	/* mask specified must be subset of hw supported mask
	 * i.e. mask | hw_mask == hw_mask
	 */
	if (!mask_is_supported(info->mask, info->hw_mask, info->len)) {
		rte_log(RTE_LOG_ERR, 0, "parse item mask is not supported\n");
		return PARSE_ERR_INVALID_MASK;
	}

	return 0;
}

static int
update_extraction_data(struct parse_state *pst, struct parse_item_info *info,
		       struct profile_xtract_info *xinfo)
{
	uint8_t int_info_mask[PROFILE_MAX_EXTRACT_DATA_LEN];
	uint8_t int_info[PROFILE_MAX_EXTRACT_DATA_LEN];
	struct profile_xtract_info *x;
	int hdr_off;
	int len = 0;

	x = xinfo;
	if (x->len > PROFILE_MAX_EXTRACT_DATA_LEN)
		return PARSE_ERR_INVALID_SIZE;

	len = x->len;
	hdr_off = x->hdr_off;

	if (hdr_off < info->hw_hdr_len)
		return 0;

	if (x->enable == 0)
		return 0;

	hdr_off -= info->hw_hdr_len;

	if (hdr_off >= info->len)
		return 0;

	if (hdr_off + len > info->len)
		len = info->len - hdr_off;

	len = check_copysz((FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS * 8) - x->key_off, len);
	if (len < 0)
		return PARSE_ERR_INVALID_SIZE;

	/* Need to reverse complete structure so that dest addr is at
	 * MSB so as to program the MCAM using parsed_data & parsed_data_mask
	 * arrays
	 */
	prep_tcam_ldata(int_info, (const uint8_t *)info->spec + hdr_off, x->len);
	prep_tcam_ldata(int_info_mask, (const uint8_t *)info->mask + hdr_off, x->len);

	memcpy(pst->parsed_data_mask + x->key_off, int_info_mask, len);
	memcpy(pst->parsed_data + x->key_off, int_info, len);
	return 0;
}

static inline void
be32_to_cpu_array(uint32_t *dst, const uint32_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = rte_be_to_cpu_32(src[i]);
}

static int
update_parse_state(struct parse_state *pst, struct parse_item_info *info, int lid, int lt,
		   uint8_t flags)
{
	struct profile_lid_lt_xtract_info *xinfo;
	struct parsed_flow_dump_data *dump;
	struct profile_xtract_info *lfinfo;
	int intf, lf_cfg;
	int i, j, rc = 0;

	pst->layer_mask |= lid;
	pst->lt[lid] = lt;
	pst->flags[lid] = flags;

	intf = pst->nix_intf;
	xinfo = &pst->parser->prx_dxcfg[intf][lid][lt];
	if (xinfo->is_terminating)
		pst->terminate = 1;

	if (info->spec == NULL)
		goto done;

	for (i = 0; i < PROFILE_MAX_LD; i++) {
		if (xinfo->xtract[i].use_hash)
			continue;
		rc = update_extraction_data(pst, info, &xinfo->xtract[i]);
		if (rc != 0)
			return rc;
	}

	for (i = 0; i < PROFILE_MAX_LD; i++) {
		if (xinfo->xtract[i].flags_enable == 0)
			continue;
		if (xinfo->xtract[i].use_hash)
			continue;

		lf_cfg = pst->parser->prx_lfcfg[i].i;
		if (lf_cfg == lid) {
			for (j = 0; j < PROFILE_MAX_LFL; j++) {
				lfinfo = pst->parser->prx_fxcfg[intf][i][j].xtract;
				rc = update_extraction_data(pst, info, &lfinfo[0]);
				if (rc != 0)
					return rc;

				if (lfinfo[0].enable)
					pst->flags[lid] = j;
			}
		}
	}

done:
	dump = &pst->flow->dump_data[pst->flow->num_patterns++];
	dump->lid = lid;
	dump->ltype = lt;
	pst->pattern++;
	return 0;
}

static const struct rte_flow_item *
parse_skip_void_and_any_items(const struct rte_flow_item *pattern)
{
	while ((pattern->type == RTE_FLOW_ITEM_TYPE_VOID) ||
	       (pattern->type == RTE_FLOW_ITEM_TYPE_ANY))
		pattern++;

	return pattern;
}

static int
parse_meta_items(struct parse_state *pst)
{
	RTE_SET_USED(pst);
	return 0;
}

static int
parse_mark_item(struct parse_state *pst)
{
	if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_MARK) {
		if (pst->flow->nix_intf != NIX_INTF_RX)
			return -EINVAL;

		pst->is_second_pass_rule = true;
		pst->pattern++;
	}

	return 0;
}

static int
flow_raw_item_prepare(const struct rte_flow_item_raw *raw_spec,
		      const struct rte_flow_item_raw *raw_mask, struct parse_item_info *info,
		      uint8_t *spec_buf, uint8_t *mask_buf)
{
	memset(spec_buf, 0, PARSER_MAX_RAW_ITEM_LEN);
	memset(mask_buf, 0, PARSER_MAX_RAW_ITEM_LEN);

	memcpy(spec_buf + raw_spec->offset, raw_spec->pattern, raw_spec->length);

	if (raw_mask && raw_mask->pattern)
		memcpy(mask_buf + raw_spec->offset, raw_mask->pattern, raw_spec->length);
	else
		memset(mask_buf + raw_spec->offset, 0xFF, raw_spec->length);

	info->len = PARSER_MAX_RAW_ITEM_LEN;
	info->spec = spec_buf;
	info->mask = mask_buf;
	return 0;
}

static int
parse_pre_l2(struct parse_state *pst)
{
	uint8_t raw_spec_buf[PARSER_MAX_RAW_ITEM_LEN] = {0};
	uint8_t raw_mask_buf[PARSER_MAX_RAW_ITEM_LEN] = {0};
	uint8_t hw_mask[PROFILE_MAX_EXTRACT_HW_LEN] = {0};
	const struct rte_flow_item_raw *raw_spec;
	struct parse_item_info info;
	int lid, lt, len;
	int rc;

	if (pst->parser->switch_header_type != PARSER_PRIV_FLAGS_PRE_L2)
		return 0;

	/* Identify the pattern type into lid, lt */
	if (pst->pattern->type != RTE_FLOW_ITEM_TYPE_RAW)
		return 0;

	lid = PROFILE_LID_LA;
	lt = PROFILE_LT_LA_CUSTOM_PRE_L2_ETHER;
	info.hw_hdr_len = 0;

	raw_spec = pst->pattern->spec;
	len = raw_spec->length + raw_spec->offset;
	if (len > PARSER_MAX_RAW_ITEM_LEN)
		return -EINVAL;

	if (raw_spec->relative == 0 || raw_spec->search || raw_spec->limit || raw_spec->offset < 0)
		return -EINVAL;

	flow_raw_item_prepare((const struct rte_flow_item_raw *)pst->pattern->spec,
			      (const struct rte_flow_item_raw *)pst->pattern->mask, &info,
			      raw_spec_buf, raw_mask_buf);

	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	hw_supp_mask(pst, &info, lid, lt);

	/* Basic validation of item parameters */
	rc = parse_item_basic(pst->pattern, &info);
	if (rc)
		return rc;

	/* Update pst if not validate only? clash check? */
	return update_parse_state(pst, &info, lid, lt, 0);
}

static int
parse_higig2_hdr(struct parse_state *pst)
{
	uint8_t hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt;
	int rc;

	/* Identify the pattern type into lid, lt */
	if (pst->pattern->type != RTE_FLOW_ITEM_TYPE_HIGIG2)
		return 0;

	lid = PROFILE_LID_LA;
	lt = PROFILE_LT_LA_HIGIG2_ETHER;
	info.hw_hdr_len = 0;

	if (pst->flow->nix_intf == NIX_INTF_TX) {
		lt = PROFILE_LT_LA_IH_NIX_HIGIG2_ETHER;
#define PROFILE_MAX_KEY_NIBBLES (31)
		info.hw_hdr_len = IH_LENGTH;
	}

	/* Prepare for parsing the item */
	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	info.len = sizeof(struct rte_flow_item_higig2_hdr);
	hw_supp_mask(pst, &info, lid, lt);
	info.spec = NULL;
	info.mask = NULL;

	/* Basic validation of item parameters */
	rc = parse_item_basic(pst->pattern, &info);
	if (rc)
		return rc;

	/* Update pst if not validate only? clash check? */
	return update_parse_state(pst, &info, lid, lt, 0);
}

static int
parse_la(struct parse_state *pst)
{
	const struct rte_flow_item_eth *eth_item;
	uint8_t hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt;
	int rc;

	/* Identify the pattern type into lid, lt */
	if (pst->pattern->type != RTE_FLOW_ITEM_TYPE_ETH)
		return 0;

	pst->has_eth_type = true;
	eth_item = pst->pattern->spec;

	lid = PROFILE_LID_LA;
	lt = PROFILE_LT_LA_ETHER;
	info.hw_hdr_len = 0;

	if (pst->flow->nix_intf == NIX_INTF_TX) {
		lt = PROFILE_LT_LA_IH_NIX_ETHER;
		info.hw_hdr_len = IH_LENGTH;
		if (pst->parser->switch_header_type == PARSER_PRIV_FLAGS_HIGIG) {
			lt = PROFILE_LT_LA_IH_NIX_HIGIG2_ETHER;
			info.hw_hdr_len += HIGIG2_LENGTH;
		}
	} else {
		if (pst->parser->switch_header_type == PARSER_PRIV_FLAGS_HIGIG) {
			lt = PROFILE_LT_LA_HIGIG2_ETHER;
			info.hw_hdr_len = HIGIG2_LENGTH;
		}
	}

	/* Prepare for parsing the item */
	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	info.len = sizeof(eth_item->hdr);
	hw_supp_mask(pst, &info, lid, lt);
	info.spec = NULL;
	info.mask = NULL;

	/* Basic validation of item parameters */
	rc = parse_item_basic(pst->pattern, &info);
	if (rc)
		return rc;

	rc = update_parse_state(pst, &info, lid, lt, 0);
	if (rc)
		return rc;

	if (eth_item && eth_item->has_vlan)
		pst->set_vlan_ltype_mask = true;

	return 0;
}

#define MAX_SUPPORTED_VLANS 3

static int
parse_vlan_count(const struct rte_flow_item *pattern, const struct rte_flow_item **pattern_list,
		 const struct rte_flow_item_vlan **vlan_items, int *vlan_count)
{
	*vlan_count = 0;
	while (pattern->type == RTE_FLOW_ITEM_TYPE_VLAN) {
		if (*vlan_count > MAX_SUPPORTED_VLANS - 1)
			return PARSE_ERR_PATTERN_NOTSUP;

		/* Don't support ranges */
		if (pattern->last != NULL)
			return PARSE_ERR_INVALID_RANGE;

		/* If spec is NULL, both mask and last must be NULL, this
		 * makes it to match ANY value (eq to mask = 0).
		 * Setting either mask or last without spec is an error
		 */
		if (pattern->spec == NULL) {
			if (pattern->last != NULL && pattern->mask != NULL)
				return PARSE_ERR_INVALID_SPEC;
		}

		pattern_list[*vlan_count] = pattern;
		vlan_items[*vlan_count] = pattern->spec;
		(*vlan_count)++;

		pattern++;
		pattern = parse_skip_void_and_any_items(pattern);
	}

	return 0;
}

static int
parse_vlan_ltype_get(struct parse_state *pst, const struct rte_flow_item_vlan **vlan_item,
		     int vlan_count, int *ltype, int *lflags)
{
	switch (vlan_count) {
	case 1:
		*ltype = PROFILE_LT_LB_CTAG;
		if (vlan_item[0] && vlan_item[0]->has_more_vlan)
			*ltype = PROFILE_LT_LB_STAG_QINQ;
		break;
	case 2:
		if (vlan_item[1] && vlan_item[1]->has_more_vlan) {
			if (!(pst->parser->keyx_supp_nmask[pst->nix_intf] &
			      0x3ULL << PROFILE_LFLAG_LB_OFFSET))
				return PARSE_ERR_PATTERN_NOTSUP;

			/* This lflag value will match either one of
			 * PROFILE_F_LB_L_WITH_STAG_STAG,
			 * PROFILE_F_LB_L_WITH_QINQ_CTAG,
			 * PROFILE_F_LB_L_WITH_QINQ_QINQ and
			 * PROFILE_F_LB_L_WITH_ITAG (0b0100 to 0b0111). For
			 * PROFILE_F_LB_L_WITH_ITAG, ltype is PROFILE_LT_LB_ETAG
			 * hence will not match.
			 */

			*lflags = PROFILE_F_LB_L_WITH_QINQ_CTAG & PROFILE_F_LB_L_WITH_QINQ_QINQ &
				  PROFILE_F_LB_L_WITH_STAG_STAG;
		}
		*ltype = PROFILE_LT_LB_STAG_QINQ;
		break;
	case 3:
		if (vlan_item[2] && vlan_item[2]->has_more_vlan)
			return PARSE_ERR_PATTERN_NOTSUP;
		if (!(pst->parser->keyx_supp_nmask[pst->nix_intf] &
		      0x3ULL << PROFILE_LFLAG_LB_OFFSET))
			return PARSE_ERR_PATTERN_NOTSUP;
		*ltype = PROFILE_LT_LB_STAG_QINQ;
		*lflags = PROFILE_F_STAG_STAG_CTAG;
		break;
	default:
		return PARSE_ERR_PATTERN_NOTSUP;
	}

	return 0;
}

static int
update_vlan_parse_state(struct parse_state *pst, const struct rte_flow_item *pattern, int lid,
			int lt, uint8_t lflags, int vlan_count)
{
	uint8_t vlan_spec[MAX_SUPPORTED_VLANS * sizeof(struct rte_vlan_hdr)];
	uint8_t vlan_mask[MAX_SUPPORTED_VLANS * sizeof(struct rte_vlan_hdr)];
	int rc = 0, i, offset = TPID_LENGTH;
	struct parse_item_info parse_info;
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];

	memset(vlan_spec, 0, sizeof(struct rte_vlan_hdr) * MAX_SUPPORTED_VLANS);
	memset(vlan_mask, 0, sizeof(struct rte_vlan_hdr) * MAX_SUPPORTED_VLANS);
	memset(&parse_info, 0, sizeof(parse_info));

	if (vlan_count > 2)
		vlan_count = 2;

	for (i = 0; i < vlan_count; i++) {
		if (pattern[i].spec)
			memcpy(vlan_spec + offset, pattern[i].spec, sizeof(struct rte_vlan_hdr));
		if (pattern[i].mask)
			memcpy(vlan_mask + offset, pattern[i].mask, sizeof(struct rte_vlan_hdr));

		offset += 4;
	}

	parse_info.def_mask = NULL;
	parse_info.spec = vlan_spec;
	parse_info.mask = vlan_mask;
	parse_info.def_mask = NULL;
	parse_info.hw_hdr_len = 0;

	lid = PROFILE_LID_LB;
	parse_info.hw_mask = hw_mask;

	if (lt == PROFILE_LT_LB_CTAG)
		parse_info.len = sizeof(struct rte_vlan_hdr) + TPID_LENGTH;

	if (lt == PROFILE_LT_LB_STAG_QINQ)
		parse_info.len = sizeof(struct rte_vlan_hdr) * 2 + TPID_LENGTH;

	memset(hw_mask, 0, sizeof(hw_mask));

	parse_info.hw_mask = &hw_mask;
	hw_supp_mask(pst, &parse_info, lid, lt);

	rc = mask_is_supported(parse_info.mask, parse_info.hw_mask, parse_info.len);
	if (!rc)
		return PARSE_ERR_INVALID_MASK;

	/* Point pattern to last item consumed */
	pst->pattern = pattern;
	return update_parse_state(pst, &parse_info, lid, lt, lflags);
}

static int
parse_lb_vlan(struct parse_state *pst)
{
	const struct rte_flow_item_vlan *vlan_items[MAX_SUPPORTED_VLANS];
	const struct rte_flow_item *pattern_list[MAX_SUPPORTED_VLANS];
	const struct rte_flow_item *last_pattern;
	int vlan_count = 0, rc = 0;
	int lid, lt, lflags;

	lid = PROFILE_LID_LB;
	lflags = 0;
	last_pattern = pst->pattern;

	rc = parse_vlan_count(pst->pattern, pattern_list, vlan_items, &vlan_count);
	if (rc)
		return rc;

	rc = parse_vlan_ltype_get(pst, vlan_items, vlan_count, &lt, &lflags);
	if (rc)
		return rc;

	if (vlan_count == 3) {
		if (pattern_list[2]->spec != NULL && pattern_list[2]->mask != NULL &&
		    pattern_list[2]->last != NULL)
			return PARSE_ERR_PATTERN_NOTSUP;

		/* Matching can be done only for two tags. */
		vlan_count = 2;
		last_pattern++;
	}

	rc = update_vlan_parse_state(pst, pattern_list[0], lid, lt, lflags, vlan_count);
	if (rc)
		return rc;

	if (vlan_count > 1)
		pst->pattern = last_pattern + vlan_count;

	return 0;
}

static int
parse_lb(struct parse_state *pst)
{
	const struct rte_flow_item *pattern = pst->pattern;
	const struct rte_flow_item *last_pattern;
	const struct rte_flow_item_raw *raw_spec;
	uint8_t raw_spec_buf[PARSER_MAX_RAW_ITEM_LEN];
	uint8_t raw_mask_buf[PARSER_MAX_RAW_ITEM_LEN];
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt, lflags, len = 0;
	int rc;

	info.def_mask = NULL;
	info.spec = NULL;
	info.mask = NULL;
	info.def_mask = NULL;
	info.hw_hdr_len = TPID_LENGTH;

	lid = PROFILE_LID_LB;
	lflags = 0;
	last_pattern = pattern;

	if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_VLAN) {
		/* RTE vlan is either 802.1q or 802.1ad,
		 * this maps to either CTAG/STAG. We need to decide
		 * based on number of VLANS present. Matching is
		 * supported on first two tags.
		 */

		return parse_lb_vlan(pst);
	} else if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_E_TAG) {
		/* we can support ETAG and match a subsequent CTAG
		 * without any matching support.
		 */
		lt = PROFILE_LT_LB_ETAG;
		lflags = 0;

		last_pattern = pst->pattern;
		pattern = parse_skip_void_and_any_items(pst->pattern + 1);
		if (pattern->type == RTE_FLOW_ITEM_TYPE_VLAN) {
			/* set supported mask to NULL for vlan tag */
			info.hw_mask = NULL;
			info.len = sizeof(struct rte_flow_item_vlan);
			rc = parse_item_basic(pattern, &info);
			if (rc != 0)
				return rc;

			lflags = PROFILE_F_ETAG_CTAG;
			last_pattern = pattern;
		}
		info.len = sizeof(struct rte_flow_item_e_tag);
	} else if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_PPPOES) {
		info.hw_mask = NULL;
		info.len = sizeof(struct rte_flow_item_pppoe);
		info.hw_hdr_len = 2;
		lt = PROFILE_LT_LB_PPPOE;
	} else if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_RAW) {
		raw_spec = pst->pattern->spec;
		if (raw_spec->relative)
			return 0;
		len = raw_spec->length + raw_spec->offset;
		if (len > PARSER_MAX_RAW_ITEM_LEN)
			return -EINVAL;

		if (pst->parser->switch_header_type == PARSER_PRIV_FLAGS_VLAN_EXDSA)
			lt = PROFILE_LT_LB_VLAN_EXDSA;
		else if (pst->parser->switch_header_type == PARSER_PRIV_FLAGS_EXDSA)
			lt = PROFILE_LT_LB_EXDSA;
		else
			return -EINVAL;

		flow_raw_item_prepare((const struct rte_flow_item_raw *)pst->pattern->spec,
				      (const struct rte_flow_item_raw *)pst->pattern->mask, &info,
				      raw_spec_buf, raw_mask_buf);

		info.hw_hdr_len = 0;
	} else {
		return 0;
	}

	info.hw_mask = &hw_mask;
	hw_supp_mask(pst, &info, lid, lt);

	rc = parse_item_basic(pst->pattern, &info);
	if (rc != 0)
		return rc;

	/* Point pattern to last item consumed */
	pst->pattern = last_pattern;
	return update_parse_state(pst, &info, lid, lt, lflags);
}

static int
parse_mpls_label_stack(struct parse_state *pst, int *flag)
{
	uint8_t flag_list[] = {0, PROFILE_F_MPLS_2_LABELS, PROFILE_F_MPLS_3_LABELS,
			       PROFILE_F_MPLS_4_LABELS};
	const struct rte_flow_item *pattern = pst->pattern;
	struct parse_item_info info;
	int nr_labels = 0;
	int rc;

	/*
	 * pst->pattern points to first MPLS label. We only check
	 * that subsequent labels do not have anything to match.
	 */
	info.def_mask = NULL;
	info.hw_mask = NULL;
	info.len = sizeof(struct rte_flow_item_mpls);
	info.spec = NULL;
	info.mask = NULL;
	info.hw_hdr_len = 0;

	while (pattern->type == RTE_FLOW_ITEM_TYPE_MPLS) {
		nr_labels++;

		/* Basic validation of Second/Third/Fourth mpls item */
		if (nr_labels > 1) {
			rc = parse_item_basic(pattern, &info);
			if (rc != 0)
				return rc;
		}
		pst->last_pattern = pattern;
		pattern++;
		pattern = parse_skip_void_and_any_items(pattern);
	}

	if (nr_labels < 1 || nr_labels > 4)
		return PARSE_ERR_PATTERN_NOTSUP;

	*flag = flag_list[nr_labels - 1];
	return 0;
}

static int
parse_mpls(struct parse_state *pst, int lid)
{
	/* Find number of MPLS labels */
	uint8_t hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lt, lflags;
	int rc;

	lflags = 0;

	if (lid == PROFILE_LID_LC)
		lt = PROFILE_LT_LC_MPLS;
	else if (lid == PROFILE_LID_LD)
		lt = PROFILE_LT_LD_TU_MPLS_IN_IP;
	else
		lt = PROFILE_LT_LE_TU_MPLS_IN_UDP;

	/* Prepare for parsing the first item */
	info.hw_mask = &hw_mask;
	info.len = sizeof(struct rte_flow_item_mpls);
	info.spec = NULL;
	info.mask = NULL;
	info.def_mask = NULL;
	info.hw_hdr_len = 0;

	hw_supp_mask(pst, &info, lid, lt);
	rc = parse_item_basic(pst->pattern, &info);
	if (rc != 0)
		return rc;

	/*
	 * Parse for more labels.
	 * This sets lflags and pst->last_pattern correctly.
	 */
	rc = parse_mpls_label_stack(pst, &lflags);
	if (rc != 0)
		return rc;

	pst->tunnel = 1;
	pst->pattern = pst->last_pattern;

	return update_parse_state(pst, &info, lid, lt, lflags);
}

static inline void
check_lc_ip_tunnel(struct parse_state *pst)
{
	const struct rte_flow_item *pattern = pst->pattern + 1;

	pattern = parse_skip_void_and_any_items(pattern);
	if (pattern->type == RTE_FLOW_ITEM_TYPE_MPLS || pattern->type == RTE_FLOW_ITEM_TYPE_IPV4 ||
	    pattern->type == RTE_FLOW_ITEM_TYPE_IPV6)
		pst->tunnel = 1;
}

static int
handle_ipv6ext_attr(const struct rte_flow_item_ipv6 *ipv6_spec, struct parse_state *pst,
		    uint8_t *flags)
{
	int flags_count = 0;

	if (ipv6_spec->has_hop_ext) {
		*flags = PROFILE_F_LC_L_EXT_HOP;
		flags_count++;
	}
	if (ipv6_spec->has_route_ext) {
		*flags = PROFILE_F_LC_L_EXT_ROUT;
		flags_count++;
	}
	if (ipv6_spec->has_frag_ext) {
		*flags = PROFILE_F_LC_U_IP6_FRAG;
		flags_count++;
	}
	if (ipv6_spec->has_dest_ext) {
		*flags = PROFILE_F_LC_L_EXT_DEST;
		flags_count++;
	}
	if (ipv6_spec->has_mobil_ext) {
		*flags = PROFILE_F_LC_L_EXT_MOBILITY;
		flags_count++;
	}
	if (ipv6_spec->has_hip_ext) {
		*flags = PROFILE_F_LC_L_EXT_HOSTID;
		flags_count++;
	}
	if (ipv6_spec->has_shim6_ext) {
		*flags = PROFILE_F_LC_L_EXT_SHIM6;
		flags_count++;
	}
	if (ipv6_spec->has_auth_ext) {
		pst->lt[PROFILE_LID_LD] = PROFILE_LT_LD_AH;
		flags_count++;
	}
	if (ipv6_spec->has_esp_ext) {
		pst->lt[PROFILE_LID_LE] = PROFILE_LT_LE_ESP;
		flags_count++;
	}

	if (flags_count > 1)
		return -EINVAL;

	if (flags_count)
		pst->set_ipv6ext_ltype_mask = true;

	return 0;
}

static int
process_ipv6_item(struct parse_state *pst)
{
	uint8_t ipv6_hdr_mask[2 * sizeof(struct rte_ipv6_hdr)];
	uint8_t ipv6_hdr_buf[2 * sizeof(struct rte_ipv6_hdr)];
	const struct rte_flow_item_ipv6 *ipv6_spec, *ipv6_mask;
	const struct rte_flow_item *pattern = pst->pattern;
	int offset = 0, rc = 0, lid, item_count = 0;
	struct parse_item_info parse_info;
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	uint8_t flags = 0, ltype;

	memset(ipv6_hdr_buf, 0, sizeof(ipv6_hdr_buf));
	memset(ipv6_hdr_mask, 0, sizeof(ipv6_hdr_mask));

	ipv6_spec = pst->pattern->spec;
	ipv6_mask = pst->pattern->mask;

	parse_info.def_mask = NULL;
	parse_info.spec = ipv6_hdr_buf;
	parse_info.mask = ipv6_hdr_mask;
	parse_info.def_mask = NULL;
	parse_info.hw_hdr_len = 0;
	parse_info.len = sizeof(ipv6_spec->hdr);

	pst->set_ipv6ext_ltype_mask = true;

	lid = PROFILE_LID_LC;
	ltype = PROFILE_LT_LC_IP6;

	if (pattern->type == RTE_FLOW_ITEM_TYPE_IPV6) {
		item_count++;
		if (ipv6_spec) {
			memcpy(ipv6_hdr_buf, &ipv6_spec->hdr, sizeof(struct rte_ipv6_hdr));
			rc = handle_ipv6ext_attr(ipv6_spec, pst, &flags);
			if (rc)
				return rc;
		}
		if (ipv6_mask)
			memcpy(ipv6_hdr_mask, &ipv6_mask->hdr, sizeof(struct rte_ipv6_hdr));
	}

	offset = sizeof(struct rte_ipv6_hdr);

	while (pattern->type != RTE_FLOW_ITEM_TYPE_END) {
		/* Don't support ranges */
		if (pattern->last != NULL)
			return PARSE_ERR_INVALID_RANGE;

		/* If spec is NULL, both mask and last must be NULL, this
		 * makes it to match ANY value (eq to mask = 0).
		 * Setting either mask or last without spec is
		 * an error
		 */
		if (pattern->spec == NULL) {
			if (pattern->last != NULL && pattern->mask != NULL)
				return PARSE_ERR_INVALID_SPEC;
		}
		/* Either one RTE_FLOW_ITEM_TYPE_IPV6_EXT or
		 * one RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT is supported
		 * following an RTE_FLOW_ITEM_TYPE_IPV6 item.
		 */
		if (pattern->type == RTE_FLOW_ITEM_TYPE_IPV6_EXT) {
			item_count++;
			ltype = PROFILE_LT_LC_IP6_EXT;
			parse_info.len = sizeof(struct rte_ipv6_hdr) +
					 sizeof(struct rte_flow_item_ipv6_frag_ext);
			if (pattern->spec)
				memcpy(ipv6_hdr_buf + offset, pattern->spec,
				       sizeof(struct rte_flow_item_ipv6_frag_ext));
			if (pattern->mask)
				memcpy(ipv6_hdr_mask + offset, pattern->mask,
				       sizeof(struct rte_flow_item_ipv6_frag_ext));
			break;
		} else if (pattern->type == RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT) {
			item_count++;
			ltype = PROFILE_LT_LC_IP6_EXT;
			flags = PROFILE_F_LC_U_IP6_FRAG;
			parse_info.len =
				sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ipv6_fragment_ext);
			if (pattern->spec)
				memcpy(ipv6_hdr_buf + offset, pattern->spec,
				       sizeof(struct rte_ipv6_fragment_ext));
			if (pattern->mask)
				memcpy(ipv6_hdr_mask + offset, pattern->mask,
				       sizeof(struct rte_ipv6_fragment_ext));

			break;
		} else if (pattern->type == RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT) {
			item_count++;
			ltype = PROFILE_LT_LC_IP6_EXT;
			parse_info.len = sizeof(struct rte_ipv6_hdr) +
					 sizeof(struct rte_flow_item_ipv6_routing_ext);

			if (pattern->spec)
				memcpy(ipv6_hdr_buf + offset, pattern->spec,
				       sizeof(struct rte_flow_item_ipv6_routing_ext));
			if (pattern->mask)
				memcpy(ipv6_hdr_mask + offset, pattern->mask,
				       sizeof(struct rte_flow_item_ipv6_routing_ext));
			break;
		}

		pattern++;
		pattern = parse_skip_void_and_any_items(pattern);
	}

	memset(hw_mask, 0, sizeof(hw_mask));

	parse_info.hw_mask = &hw_mask;
	hw_supp_mask(pst, &parse_info, lid, ltype);

	rc = mask_is_supported(parse_info.mask, parse_info.hw_mask, parse_info.len);
	if (!rc)
		return PARSE_ERR_INVALID_MASK;

	rc = update_parse_state(pst, &parse_info, lid, ltype, flags);
	if (rc)
		return rc;

	/* update_parse_state() increments pattern once.
	 * Check if additional increment is required.
	 */
	if (item_count == 2)
		pst->pattern++;

	return 0;
}

static int
parse_lc(struct parse_state *pst)
{
	const struct rte_flow_item_raw *raw_spec;
	uint8_t raw_spec_buf[PARSER_MAX_RAW_ITEM_LEN];
	uint8_t raw_mask_buf[PARSER_MAX_RAW_ITEM_LEN];
	uint8_t hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int rc, lid, lt, len = 0;
	uint8_t flags = 0;

	if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_MPLS)
		return parse_mpls(pst, PROFILE_LID_LC);

	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	info.spec = NULL;
	info.mask = NULL;
	info.hw_hdr_len = 0;
	lid = PROFILE_LID_LC;

	switch (pst->pattern->type) {
	case RTE_FLOW_ITEM_TYPE_IPV4:
		lt = PROFILE_LT_LC_IP;
		info.len = sizeof(struct rte_flow_item_ipv4);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
	case RTE_FLOW_ITEM_TYPE_IPV6_EXT:
	case RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT:
	case RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT:
		return process_ipv6_item(pst);
	case RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4:
		lt = PROFILE_LT_LC_ARP;
		info.len = sizeof(struct rte_flow_item_arp_eth_ipv4);
		break;
	case RTE_FLOW_ITEM_TYPE_RAW:
		raw_spec = pst->pattern->spec;
		if (!raw_spec->relative)
			return 0;

		len = raw_spec->length + raw_spec->offset;
		if (len > PARSER_MAX_RAW_ITEM_LEN)
			return -EINVAL;

		flow_raw_item_prepare((const struct rte_flow_item_raw *)pst->pattern->spec,
				      (const struct rte_flow_item_raw *)pst->pattern->mask, &info,
				      raw_spec_buf, raw_mask_buf);

		lid = PROFILE_LID_LC;
		lt = PROFILE_LT_LC_NGIO;
		info.hw_mask = &hw_mask;
		hw_supp_mask(pst, &info, lid, lt);
		break;
	default:
		/* No match at this layer */
		return 0;
	}

	/* Identify if IP tunnels MPLS or IPv4/v6 */
	check_lc_ip_tunnel(pst);

	hw_supp_mask(pst, &info, lid, lt);
	rc = parse_item_basic(pst->pattern, &info);

	if (rc != 0)
		return rc;

	return update_parse_state(pst, &info, lid, lt, flags);
}

static int
parse_ld(struct parse_state *pst)
{
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt, lflags;
	int rc;

	if (pst->tunnel) {
		/* We have already parsed MPLS or IPv4/v6 followed
		 * by MPLS or IPv4/v6. Subsequent TCP/UDP etc
		 * would be parsed as tunneled versions. Skip
		 * this layer, except for tunneled MPLS. If LC is
		 * MPLS, we have anyway skipped all stacked MPLS
		 * labels.
		 */
		if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_MPLS)
			return parse_mpls(pst, PROFILE_LID_LD);
		return 0;
	}
	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	info.spec = NULL;
	info.mask = NULL;
	info.len = 0;
	info.hw_hdr_len = 0;

	lid = PROFILE_LID_LD;
	lflags = 0;

	switch (pst->pattern->type) {
	case RTE_FLOW_ITEM_TYPE_ICMP:
		if (pst->lt[PROFILE_LID_LC] == PROFILE_LT_LC_IP6)
			lt = PROFILE_LT_LD_ICMP6;
		else
			lt = PROFILE_LT_LD_ICMP;
		info.len = sizeof(struct rte_flow_item_icmp);
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		lt = PROFILE_LT_LD_UDP;
		info.len = sizeof(struct rte_flow_item_udp);
		break;
	case RTE_FLOW_ITEM_TYPE_IGMP:
		lt = PROFILE_LT_LD_IGMP;
		info.len = sizeof(struct rte_flow_item_igmp);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		lt = PROFILE_LT_LD_TCP;
		info.len = sizeof(struct rte_flow_item_tcp);
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		lt = PROFILE_LT_LD_SCTP;
		info.len = sizeof(struct rte_flow_item_sctp);
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		lt = PROFILE_LT_LD_GRE;
		info.len = sizeof(struct rte_flow_item_gre);
		pst->tunnel = 1;
		break;
	case RTE_FLOW_ITEM_TYPE_GRE_KEY:
		lt = PROFILE_LT_LD_GRE;
		info.len = sizeof(uint32_t);
		info.hw_hdr_len = 4;
		pst->tunnel = 1;
		break;
	case RTE_FLOW_ITEM_TYPE_NVGRE:
		lt = PROFILE_LT_LD_NVGRE;
		lflags = PROFILE_F_GRE_NVGRE;
		info.len = sizeof(struct rte_flow_item_nvgre);
		/* Further IP/Ethernet are parsed as tunneled */
		pst->tunnel = 1;
		break;
	default:
		return 0;
	}

	hw_supp_mask(pst, &info, lid, lt);
	rc = parse_item_basic(pst->pattern, &info);
	if (rc != 0)
		return rc;

	return update_parse_state(pst, &info, lid, lt, lflags);
}

static int
parse_le(struct parse_state *pst)
{
	const struct rte_flow_item *pattern = pst->pattern;
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt, lflags;
	int rc;

	if (pst->tunnel)
		return 0;

	if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_MPLS)
		return parse_mpls(pst, PROFILE_LID_LE);

	info.spec = NULL;
	info.mask = NULL;
	info.hw_mask = NULL;
	info.def_mask = NULL;
	info.len = 0;
	info.hw_hdr_len = 0;
	lid = PROFILE_LID_LE;
	lflags = 0;

	/* Ensure we are not matching anything in UDP */
	rc = parse_item_basic(pattern, &info);
	if (rc)
		return rc;

	info.hw_mask = &hw_mask;
	pattern = parse_skip_void_and_any_items(pattern);
	switch (pattern->type) {
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		lflags = PROFILE_F_UDP_VXLAN;
		info.len = sizeof(struct rte_flow_item_vxlan);
		lt = PROFILE_LT_LE_VXLAN;
		break;
	case RTE_FLOW_ITEM_TYPE_GTPC:
		lflags = PROFILE_F_UDP_GTP_GTPC;
		info.len = sizeof(struct rte_flow_item_gtp);
		lt = PROFILE_LT_LE_GTPC;
		break;
	case RTE_FLOW_ITEM_TYPE_GTPU:
		lflags = PROFILE_F_UDP_GTP_GTPU_G_PDU;
		info.len = sizeof(struct rte_flow_item_gtp);
		lt = PROFILE_LT_LE_GTPU;
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE:
		lflags = PROFILE_F_UDP_GENEVE;
		info.len = sizeof(struct rte_flow_item_geneve);
		lt = PROFILE_LT_LE_GENEVE;
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
		lflags = PROFILE_F_UDP_VXLANGPE;
		info.len = sizeof(struct rte_flow_item_vxlan_gpe);
		lt = PROFILE_LT_LE_VXLANGPE;
		break;
	case RTE_FLOW_ITEM_TYPE_ESP:
		lt = PROFILE_LT_LE_ESP;
		info.len = sizeof(struct rte_flow_item_esp);
		break;
	default:
		return 0;
	}

	pst->tunnel = 1;

	hw_supp_mask(pst, &info, lid, lt);
	rc = parse_item_basic(pattern, &info);
	if (rc != 0)
		return rc;

	return update_parse_state(pst, &info, lid, lt, lflags);
}

static int
parse_lf(struct parse_state *pst)
{
	const struct rte_flow_item *pattern, *last_pattern;
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	const struct rte_flow_item_eth *eth_item;
	struct parse_item_info info;
	int lid, lt, lflags;
	int nr_vlans = 0;
	int rc;

	/* We hit this layer if there is a tunneling protocol */
	if (!pst->tunnel)
		return 0;

	if (pst->pattern->type != RTE_FLOW_ITEM_TYPE_ETH)
		return 0;

	lid = PROFILE_LID_LF;
	lt = PROFILE_LT_LF_TU_ETHER;
	lflags = 0;

	eth_item = pst->pattern->spec;

	/* No match support for vlan tags */
	info.def_mask = NULL;
	info.hw_mask = NULL;
	info.len = sizeof(eth_item->hdr);
	info.spec = NULL;
	info.mask = NULL;
	info.hw_hdr_len = 0;

	/* Look ahead and find out any VLAN tags. These can be
	 * detected but no data matching is available.
	 */
	last_pattern = pst->pattern;
	pattern = pst->pattern + 1;
	pattern = parse_skip_void_and_any_items(pattern);
	while (pattern->type == RTE_FLOW_ITEM_TYPE_VLAN) {
		nr_vlans++;
		last_pattern = pattern;
		pattern++;
		pattern = parse_skip_void_and_any_items(pattern);
	}
	switch (nr_vlans) {
	case 0:
		break;
	case 1:
		lflags = PROFILE_F_TU_ETHER_CTAG;
		break;
	case 2:
		lflags = PROFILE_F_TU_ETHER_STAG_CTAG;
		break;
	default:
		return PARSE_ERR_PATTERN_NOTSUP;
	}

	info.hw_mask = &hw_mask;
	info.len = sizeof(eth_item->hdr);
	info.hw_hdr_len = 0;
	hw_supp_mask(pst, &info, lid, lt);
	info.spec = NULL;
	info.mask = NULL;

	if (eth_item && eth_item->has_vlan)
		pst->set_vlan_ltype_mask = true;

	rc = parse_item_basic(pst->pattern, &info);
	if (rc != 0)
		return rc;

	pst->pattern = last_pattern;

	return update_parse_state(pst, &info, lid, lt, lflags);
}

static int
parse_lg(struct parse_state *pst)
{
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt;
	int rc;

	if (!pst->tunnel)
		return 0;

	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	info.spec = NULL;
	info.mask = NULL;
	info.hw_hdr_len = 0;
	lid = PROFILE_LID_LG;

	if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_IPV4) {
		lt = PROFILE_LT_LG_TU_IP;
		info.len = sizeof(struct rte_flow_item_ipv4);
	} else if (pst->pattern->type == RTE_FLOW_ITEM_TYPE_IPV6) {
		lt = PROFILE_LT_LG_TU_IP6;
		info.len = sizeof(struct rte_flow_item_ipv6);
	} else {
		/* There is no tunneled IP header */
		return 0;
	}

	hw_supp_mask(pst, &info, lid, lt);
	rc = parse_item_basic(pst->pattern, &info);
	if (rc != 0)
		return rc;

	return update_parse_state(pst, &info, lid, lt, 0);
}

static int
parse_lh(struct parse_state *pst)
{
	char hw_mask[PROFILE_MAX_EXTRACT_HW_LEN];
	struct parse_item_info info;
	int lid, lt;
	int rc;

	if (!pst->tunnel)
		return 0;

	info.def_mask = NULL;
	info.hw_mask = &hw_mask;
	info.spec = NULL;
	info.mask = NULL;
	info.hw_hdr_len = 0;
	lid = PROFILE_LID_LH;

	switch (pst->pattern->type) {
	case RTE_FLOW_ITEM_TYPE_UDP:
		lt = PROFILE_LT_LH_TU_UDP;
		info.len = sizeof(struct rte_flow_item_udp);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		lt = PROFILE_LT_LH_TU_TCP;
		info.len = sizeof(struct rte_flow_item_tcp);
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		lt = PROFILE_LT_LH_TU_SCTP;
		info.len = sizeof(struct rte_flow_item_sctp);
		break;
	case RTE_FLOW_ITEM_TYPE_ESP:
		lt = PROFILE_LT_LH_TU_ESP;
		info.len = sizeof(struct rte_flow_item_esp);
		break;
	default:
		return 0;
	}

	hw_supp_mask(pst, &info, lid, lt);
	rc = parse_item_basic(pst->pattern, &info);
	if (rc != 0)
		return rc;

	return update_parse_state(pst, &info, lid, lt, 0);
}

typedef int (*parse_stage_func_t)(struct parse_state *pst);

static int
parse_pattern(struct flow_parser *parser, const struct rte_flow_item pattern[],
	      struct parsed_flow *flow, struct parse_state *pst)
{
	parse_stage_func_t parse_stage_funcs[] = {
		parse_meta_items, parse_mark_item, parse_pre_l2, parse_higig2_hdr,
		parse_la,         parse_lb,        parse_lc,     parse_ld,
		parse_le,         parse_lf,        parse_lg,     parse_lh,
	};
	uint8_t layer = 0;
	int key_offset;
	int rc;

	if (pattern == NULL)
		return PARSE_ERR_PARAM;

	pst->parser = parser;
	pst->flow = flow;
	pst->nix_intf = flow->nix_intf;

	/* Use integral byte offset */
	key_offset = pst->parser->keyx_len[flow->nix_intf];
	key_offset = (key_offset + 7) / 8;

	/* Location where LDATA would begin */
	pst->parsed_data = (uint8_t *)flow->parsed_data;
	pst->parsed_data_mask = (uint8_t *)flow->parsed_data_mask;

	while (pattern->type != RTE_FLOW_ITEM_TYPE_END && layer < RTE_DIM(parse_stage_funcs)) {
		/* Skip place-holders */
		pattern = parse_skip_void_and_any_items(pattern);

		pst->pattern = pattern;
		rc = parse_stage_funcs[layer](pst);
		if (rc != 0) {
			dao_info("Failed to parse layer %d, rc %d", layer, rc);
			return rc;
		}

		layer++;

		/*
		 * Parse stage function sets pst->pattern to
		 * 1 past the last item it consumed.
		 */
		pattern = pst->pattern;

		if (pst->terminate)
			break;
	}

	/* Skip trailing place-holders */
	pattern = parse_skip_void_and_any_items(pattern);

	/* Are there more items than what we can handle? */
	if (pattern->type != RTE_FLOW_ITEM_TYPE_END)
		return PARSE_ERR_PATTERN_NOTSUP;

	return 0;
}

static int
parse_attr(struct flow_parser *parser, const struct rte_flow_attr *attr, struct parsed_flow *flow)
{
	uint8_t attributes;

	RTE_SET_USED(parser);
	if (attr == NULL)
		return PARSE_ERR_PARAM;

	/* Check if none or more than one attributes set */
	attributes = attr->egress + attr->ingress + attr->transfer;
	if ((!attributes) || (attributes > 1))
		return PARSE_ERR_PARAM;

	if (attr->ingress || attr->transfer)
		flow->nix_intf = FLOW_PARSER_INTF_RX;
	else
		flow->nix_intf = FLOW_PARSER_INTF_TX;

	flow->priority = attr->priority;
	return 0;
}

static int
parse_rule(struct flow_parser *parser, const struct rte_flow_attr *attr,
	   const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
	   struct parsed_flow *flow, struct parse_state *pst)
{
	int err;

	RTE_SET_USED(actions);
	/* Check attr */
	err = parse_attr(parser, attr, flow);
	if (err)
		return err;

	/* Check pattern */
	err = parse_pattern(parser, pattern, flow, pst);
	if (err)
		return err;

	return 0;
}

struct parsed_flow *
flow_parse(struct flow_parser *parser, const struct rte_flow_attr *attr,
	   const struct rte_flow_item pattern[], const struct rte_flow_action actions[])
{
	struct parse_state parse_state = {0};
	struct parsed_flow *flow = NULL;
	int rc;

	flow = rte_zmalloc("cnxk", sizeof(*flow), 0);
	if (flow == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	rc = parse_rule(parser, attr, pattern, actions, flow, &parse_state);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to parse rule");

	rc = populate_parsed_data(parser, &parse_state, 0);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to set layer types");

	return flow;
fail:
	return NULL;
}

int
flow_parser_init(struct flow_parser *parser, struct flow_parser_tcam_kex *parse_prfl)
{
	struct profile_cfg_rsp profile_cfg;

	memset(parser, 0, sizeof(*parser));
	memset(&profile_cfg, 0, sizeof(profile_cfg));

	profile_cfg.rx_keyx_cfg = parse_prfl->keyx_cfg[0];
	profile_cfg.tx_keyx_cfg = parse_prfl->keyx_cfg[1];
	memcpy(&profile_cfg.kex_ld_flags, &parse_prfl->kex_ld_flags,
	       sizeof(profile_cfg.kex_ld_flags));
	memcpy(&profile_cfg.intf_lid_lt_ld, &parse_prfl->intf_lid_lt_ld,
	       sizeof(profile_cfg.intf_lid_lt_ld));
	memcpy(&profile_cfg.intf_ld_flags, &parse_prfl->intf_ld_flags,
	       sizeof(profile_cfg.intf_ld_flags));
	memcpy(&profile_cfg.mkex_pfl_name, &parse_prfl->name, sizeof(profile_cfg.mkex_pfl_name));

	process_profile_cfg(parser, &profile_cfg);

	parser->rx_parse_nibble = parser->keyx_supp_nmask[PROFILE_CAM_RX];

	return 0;
}
