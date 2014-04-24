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
 * $Id: lpi_blizzard.cc 62 2011-02-03 04:37:32Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_blizzard(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_both(data, "\x10\xdf\x22\x00", "\x10\x00\x00\x00"))
                return true;

        if (MATCH(data->payload[0], 0x00, ANY, 0xed, 0x01) &&
                MATCH(data->payload[1], 0x00, 0x06, 0xec, 0x01))
                return true;
        if (MATCH(data->payload[1], 0x00, ANY, 0xed, 0x01) &&
                MATCH(data->payload[0], 0x00, 0x06, 0xec, 0x01))
                return true;

	return false;
}

static lpi_module_t lpi_blizzard = {
	LPI_PROTO_BLIZZARD,
	LPI_CATEGORY_GAMING,
	"Blizzard",
	2,
	match_blizzard
};

void register_blizzard(LPIModuleMap *mod_map) {
	register_protocol(&lpi_blizzard, mod_map);
}

