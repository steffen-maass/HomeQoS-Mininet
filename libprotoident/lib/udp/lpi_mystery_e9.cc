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
 * $Id: lpi_mystery_e9.cc 104 2011-11-02 01:58:43Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_e9_payload(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0xe9, 0x82, ANY, ANY)) {
                if (len == 58)
                        return true;
                if (len == 28)
                        return true;
        }

        if (MATCH(payload, 0xe9, 0x83, ANY, ANY)) {
                if (len == 23)
                        return true;
                if (len == 28)
                        return true;
                if (len == 46)
                        return true;
        }

        if (MATCH(payload, 0xe9, 0x60, ANY, ANY)) {
                if (len == 34) 
                        return true;
        }

        return false;

}


static inline bool match_mystery_e9(lpi_data_t *data, lpi_module_t *mod UNUSED) {
	if (data->payload_len[1] == 0) {
		if (match_e9_payload(data->payload[0], data->payload_len[0]))
			return true;
	}
	if (data->payload_len[0] == 0) {
		if (match_e9_payload(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	/* Bytes 3 and 4 of payload should match */

        if ((data->payload[0] & 0xffff0000) != (data->payload[1] & 0xffff0000))
                return false;

        if (!match_e9_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_e9_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;

}

static lpi_module_t lpi_mystery_e9 = {
	LPI_PROTO_UDP_MYSTERY_E9,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_E9",
	250,
	match_mystery_e9
};

void register_mystery_e9(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_e9, mod_map);
}

