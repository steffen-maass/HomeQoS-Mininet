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
 * $Id: lpi_qqlive.cc 106 2011-11-16 21:49:48Z salcock $
 */

#include <string.h>
#include <stdio.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

typedef struct qqlive_header {
	uint8_t fe;
	uint16_t len;
	uint8_t zero;
} qqlive_hdr_t;

static inline bool match_qqlive_payload(uint32_t payload, uint32_t len) {

        uint8_t *ptr;
	uint32_t swap;

        /* This appears to have a 3 byte header. First byte is always 0xfe.
         * Second and third bytes are the length (minus the 3 byte header).
         */

        if (len == 0)
                return true;

        if (!MATCH(payload, 0xfe, ANY, ANY, 0x00))
                return false;

	swap = htonl(payload);
	swap = (swap & 0xffff00) >> 8;

        if (ntohs(swap) == len - 3)
                return true;

        return false;

}


static inline bool match_qqlive(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
		if (data->server_port == 53 || data->client_port == 53)
			return false;
	}

        if (!match_qqlive_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_qqlive_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;
}

static lpi_module_t lpi_qqlive = {
	LPI_PROTO_UDP_QQLIVE,
	LPI_CATEGORY_P2PTV,
	"QQLive",
	4,
	match_qqlive
};

void register_qqlive(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qqlive, mod_map);
}

