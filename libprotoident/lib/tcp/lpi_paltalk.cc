/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: lpi_paltalk.cc 107 2011-11-25 00:36:11Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_pal_17f6(uint32_t payload, uint32_t len) {

	if (len != 8)
		return false;
	if (MATCH(payload, 0x17, 0xf6, 0x00, 0x01))
		return true;
	return false;

}

static inline bool match_pal_24c2(uint32_t payload, uint32_t len) {
	
	if (len != 4)
		return false;
	if (MATCH(payload, 0x00, 0x00, 0x24, 0xc2))
		return true;
	return false;

}

static inline bool match_pal_ff8b(uint32_t payload, uint32_t len) {

	if (len != 24)
		return false;
	if (MATCHSTR(payload, "\xff\x8b\x00\x0e"))
		return true;
	return false;

}

static inline bool match_pal_fb(uint32_t payload, uint32_t len) {

	if (len != 6)
		return false;
	if (MATCH(payload, 0xfb, ANY, 0x00, ANY))
		return true;
	return false;

}

static inline bool match_pal_1byte(uint32_t payload, uint32_t len) {

	if (len != 0 and len != 1)
		return false;
	if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
		return true;

	return false;
}

static inline bool match_pal_4byte(uint32_t payload, uint32_t len) {

	if (len != 4)
		return false;
	if (payload == 0)
		return false;

	if (MATCH(payload, 0x00, 0x00, ANY, ANY))
		return true;
	return false;

}

static inline bool match_paltalk(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Created all these rules based on a capture of actual Paltalk
	 * traffic */

	if (match_pal_fb(data->payload[0], data->payload_len[0])) {
		if (match_pal_ff8b(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	if (match_pal_fb(data->payload[1], data->payload_len[1])) {
		if (match_pal_ff8b(data->payload[0], data->payload_len[0]))
			return true;
	}

	if (match_pal_17f6(data->payload[0], data->payload_len[0])) {
		if (match_pal_24c2(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	if (match_pal_17f6(data->payload[1], data->payload_len[1])) {
		if (match_pal_24c2(data->payload[0], data->payload_len[0]))
			return true;
	}


	/* These last two may be iffy, keep an eye out for false positives */
	if (match_pal_4byte(data->payload[0], data->payload_len[0])) {
		if (match_pal_1byte(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	if (match_pal_4byte(data->payload[1], data->payload_len[1])) {
		if (match_pal_1byte(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_paltalk = {
	LPI_PROTO_PALTALK,
	LPI_CATEGORY_CHAT,
	"Paltalk",
	11,
	match_paltalk
};

void register_paltalk(LPIModuleMap *mod_map) {
	register_protocol(&lpi_paltalk, mod_map);
}

