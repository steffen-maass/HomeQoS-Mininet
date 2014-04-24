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
 * $Id: lpi_garena.cc 112 2012-02-03 03:41:03Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_garena(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* http://garenalinux.pastebay.com/71533 */

        if (data->server_port == 53 || data->client_port == 53)
                return false;
        
	/* Garena is NOT always on port 1513 */

        /* Matching HELLO in each direction */
        if (MATCH(data->payload[0], 0x02, 0x00, 0x00, 0x00)) {
                if (data->payload_len[0] != 16)
                        return false;
                if (data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] != 16)
                        return false;
                if (MATCH(data->payload[1], 0x02, 0x00, 0x00, 0x00))
                        return true;
                if (MATCH(data->payload[1], 0x0f, 0x00, 0x00, 0x00))
                        return true;
                return false;
        }

        if (MATCH(data->payload[1], 0x02, 0x00, 0x00, 0x00)) {
                if (data->payload_len[1] != 16)
                        return false;
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[0] != 16)
                        return false;
                if (MATCH(data->payload[0], 0x02, 0x00, 0x00, 0x00))
                        return true;
                if (MATCH(data->payload[0], 0x0f, 0x00, 0x00, 0x00))
                        return true;
                return false;
        }
	

	return false;
}

static lpi_module_t lpi_garena = {
	LPI_PROTO_UDP_GARENA,
	LPI_CATEGORY_GAMING,
	"Garena_UDP",
	5,
	match_garena
};

void register_garena(LPIModuleMap *mod_map) {
	register_protocol(&lpi_garena, mod_map);
}

