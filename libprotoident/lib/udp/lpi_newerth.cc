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
 * $Id: lpi_newerth.cc 65 2011-02-07 04:08:00Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_newerth_payload(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;
        if (MATCH(payload, 0x00, 0x00, 0x01, 0x66))
                return true;
        if (MATCH(payload, 0x00, 0x00, 0x01, 0xca) && len == 6)
                return true;
        return false;
}


static inline bool match_newerth(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_newerth_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_newerth_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;


}

static lpi_module_t lpi_newerth = {
	LPI_PROTO_UDP_NEWERTH,
	LPI_CATEGORY_GAMING,
	"NewerthGames",
	3,
	match_newerth
};

void register_newerth(LPIModuleMap *mod_map) {
	register_protocol(&lpi_newerth, mod_map);
}

