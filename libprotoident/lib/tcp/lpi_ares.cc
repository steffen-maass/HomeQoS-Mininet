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
 * $Id: lpi_ares.cc 107 2011-11-25 00:36:11Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_ares_client(uint32_t payload, uint32_t len) {
	if (len != 6)
		return false;
	
	if (!MATCH(payload, 0x03, 0x00, 0x5a, 0x06))
		return false;

	return true;
}

static inline bool match_ares_peer(uint32_t payload, uint32_t len) {

	if (len != 138)
		return false;

	if (MATCH(payload, 0x87, 0x00, 0x3c, ANY))
		return true;
	if (MATCH(payload, 0x87, 0x00, 0x3b, ANY))
		return true;

	return false;

}

static inline bool match_ares(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Pretty sure this is the ARES p2p protocol */
	if (match_str_either(data, "ARES"))
		return true;

	if (match_ares_client(data->payload[0], data->payload_len[0])) {
		if (match_ares_peer(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	if (match_ares_client(data->payload[1], data->payload_len[1])) {
		if (match_ares_peer(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_ares = {
	LPI_PROTO_ARES,
	LPI_CATEGORY_P2P,
	"Ares",
	8,
	match_ares
};

void register_ares(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ares, mod_map);
}

