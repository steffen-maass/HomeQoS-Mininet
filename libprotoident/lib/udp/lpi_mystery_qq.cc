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
 * $Id: lpi_mystery_qq.cc 77 2011-04-15 04:54:37Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_qq_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len != 24)
		return false;
	if (MATCH(payload, 0x51, 0x51, 0x05, 0x00))
		return true;
	return false;

}

static inline bool match_mystery_qq(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Not to be confused with Tencent QQ.
	 *
	 * This is almost certainly a gaming protocol related to the
	 * PlayStation (based on port number).
	 */

	if (data->server_port != 3658 && data->client_port != 3658) 
		return false;

	if (match_qq_payload(data->payload[0], data->payload_len[0])) {
		if (match_qq_payload(data->payload[1], data->payload_len[1]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_mystery_qq = {
	LPI_PROTO_UDP_MYSTERY_QQ,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_QQ",
	2,
	match_mystery_qq
};

void register_mystery_qq(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_qq, mod_map);
}

