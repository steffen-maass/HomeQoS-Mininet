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
 * $Id: lpi_real.cc 64 2011-02-04 04:09:43Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_real(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* The Real Data Transport is not explicitly documented in full,
         * but these packets seem to resemble those examples we have been able
         * to find.
         *
         * https://protocol.helixcommunity.org/2005/devdocs/RDT_Feature_Level_30.txt
         */

        if (!match_str_both(data, "\x00\xff\x03\x00", "\x00\xff\x04\x49"))
                return false;

        if (data->payload_len[0] == 3 && data->payload_len[1] == 11)
                return true;
        if (data->payload_len[1] == 3 && data->payload_len[0] == 11)
                return true;
	

	return false;
}

static lpi_module_t lpi_real = {
	LPI_PROTO_UDP_REAL,
	LPI_CATEGORY_STREAMING,
	"RealPlayer",
	3,
	match_real
};

void register_real(LPIModuleMap *mod_map) {
	register_protocol(&lpi_real, mod_map);
}

