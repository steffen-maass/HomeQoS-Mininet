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
 * $Id: lpi_eso.cc 76 2011-04-08 04:45:36Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_eso_payload(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (len == 40 && MATCH(payload, 0x00, ANY, ANY, ANY))
                return true;
        if (len == 10 && MATCH(payload, 0x07, 0xa9, 0x00, 0x00))
                return true;

        return false;

}


static inline bool match_eso(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* I'm pretty sure this is Ensemble game traffic, as it is the
         * only thing I can find matching the port 2300 that it commonly
         * occurs on. No game docs available, though :( */

        if (!match_eso_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_eso_payload(data->payload[1], data->payload_len[1]))
                return false;
        return true;
	

}

static lpi_module_t lpi_eso = {
	LPI_PROTO_UDP_ESO,
	LPI_CATEGORY_GAMING,
	"EnsembleOnline",
	12,
	match_eso
};

void register_eso(LPIModuleMap *mod_map) {
	register_protocol(&lpi_eso, mod_map);
}

