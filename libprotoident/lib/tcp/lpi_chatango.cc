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
 * $Id: lpi_chatango.cc 127 2012-10-18 03:41:36Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_chatango_in(uint32_t payload, uint32_t len) {

	if (len != 2)
		return false;
	if (!MATCH(payload, 'v', 0x00, 0x00, 0x00))
		return false;

	return true;

}

static inline bool match_chatango_out(uint32_t payload, uint32_t len) {

	if (len != 10)
		return false;
	if (MATCH(payload, 'v', ':', '1', '0'))
		return true;
	if (MATCH(payload, 'v', ':', '1', '4'))
		return true;

	return false;

}

static inline bool match_chatango(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_chatango_out(data->payload[0], data->payload_len[0])) {
		if (match_chatango_in(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_chatango_in(data->payload[0], data->payload_len[0])) {
		if (match_chatango_out(data->payload[1], data->payload_len[1]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_chatango = {
	LPI_PROTO_CHATANGO,
	LPI_CATEGORY_CHAT,
	"Chatango",
	3,
	match_chatango
};

void register_chatango(LPIModuleMap *mod_map) {
	register_protocol(&lpi_chatango, mod_map);
}

