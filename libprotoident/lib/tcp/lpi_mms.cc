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
 * $Id: lpi_mms.cc 69 2011-03-10 22:38:10Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_mms_server(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x01, 0x00, 0x00, ANY))
                return true;
        return false;

}

static inline bool match_mms_client(uint32_t payload, uint32_t len) {

        if (len != 144)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x00, ANY))
                return true;
        return false;

}


static inline bool match_mms(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Microsoft Media Server protocol */

        if (match_mms_server(data->payload[0], data->payload_len[0])) {
                if (match_mms_client(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_mms_server(data->payload[1], data->payload_len[1])) {
                if (match_mms_client(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_mms = {
	LPI_PROTO_MMS,
	LPI_CATEGORY_STREAMING,
	"MMS",
	6,
	match_mms
};

void register_mms(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mms, mod_map);
}

