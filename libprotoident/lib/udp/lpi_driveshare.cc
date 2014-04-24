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
 * $Id: lpi_driveshare.cc 103 2011-10-25 04:01:45Z salcock $
 */

#include <string.h>
#include <stdio.h>
#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_driveshare_payload(uint32_t pload, uint32_t len) {

	/* I *think* this is driveshare, which seems to do SMB-like things
	 * on port 8109 UDP */

	if (len == ntohl(pload)) {
		return true;
	}
	if (MATCH(pload, 0x00, 0x00, 0x00, 0x00) && len == 48) {
		return true;
	}

	return false;

}

static inline bool match_driveshare(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Add a port restriction here, just to be safe */
	if (data->client_port != 8109 && data->server_port != 8109)
		return false;

	if (!match_driveshare_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_driveshare_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

static lpi_module_t lpi_driveshare = {
	LPI_PROTO_UDP_DRIVESHARE,
	LPI_CATEGORY_FILES,
	"DriveShare",
	12,
	match_driveshare
};

void register_driveshare(LPIModuleMap *mod_map) {
	register_protocol(&lpi_driveshare, mod_map);
}

