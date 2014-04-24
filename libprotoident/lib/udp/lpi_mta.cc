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
 * $Id: lpi_mta.cc 65 2011-02-07 04:08:00Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_ase_ping(lpi_data_t *data) {

        /* Commonly used by MultiTheftAuto - the use of "ping" and
         * "Ping" is not documented though */

        if (MATCHSTR(data->payload[0], "ping")) {
                if (data->payload_len[0] != 16)
                        return false;
                if (data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] != 16)
                        return false;
                if (MATCHSTR(data->payload[1], "Ping"))
                        return true;
                return false;
        }

        if (MATCHSTR(data->payload[1], "ping")) {
                if (data->payload_len[1] != 16)
                        return false;
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[0] != 16)
                        return false;
                if (MATCHSTR(data->payload[0], "Ping"))
                        return true;
                return false;
        }

        return false;

}


static inline bool match_mta(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Multitheftauto uses ASE on UDP to ping servers */
	if (match_ase_ping(data))
		return true;
	return false;
}

static lpi_module_t lpi_mta = {
	LPI_PROTO_UDP_MTA,
	LPI_CATEGORY_GAMING,
	"MultiTheftAuto",
	5,
	match_mta
};

void register_mta(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mta, mod_map);
}

