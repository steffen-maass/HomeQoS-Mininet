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
 * $Id: lpi_rdp.cc 107 2011-11-25 00:36:11Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_rdp_payload(uint32_t payload, uint32_t len) {

	uint32_t stated_len = 0;

        /* RDP is transported via TPKT
         *
         * TPKT header is 03 00 + 2 bytes of length (including the TPKT header)
         */

        if (!MATCH(payload, 0x03, 0x00, ANY, ANY))
                return false;

        stated_len = ntohl(payload) & 0xffff;
        if (stated_len != len)
                return false;
        return true;
	

}

static bool match_rdp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_rdp_payload(data->payload[0], data->payload_len[0])) {
		if (match_rdp_payload(data->payload[1], data->payload_len[1]))
			return true;
		
		/* Some RDP responses seem to be encrypted - not sure if this
		 * payload length is common to all flows */
		if (data->payload_len[1] == 309) 
		{
			if (data->server_port == 3389)
				return true;
			if (data->client_port == 3389) 
				return true;
		}
	}
	if (match_rdp_payload(data->payload[1], data->payload_len[1])) {
		if (data->payload_len[0] == 309) {
			if (data->server_port == 3389)
				return true;
			if (data->client_port == 3389) 
				return true;
		}
	}
	return false;
}

static lpi_module_t lpi_rdp = {
	LPI_PROTO_RDP,
	LPI_CATEGORY_REMOTE,
	"RDP",
	4, /*  Moving this to 4 purely on gut feeling */
	match_rdp
};

void register_rdp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rdp, mod_map);
}
