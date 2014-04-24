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
 * $Id: lpi_xfire_p2p.cc 65 2011-02-07 04:08:00Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_xfire_p2p(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_both(data, "SC01", "CK01"))
                return true;
        if (match_str_either(data, "MC01"))
                return true;

	return false;
}

static lpi_module_t lpi_xfire_p2p = {
	LPI_PROTO_UDP_XFIRE_P2P,
	LPI_CATEGORY_P2P,
	"Xfire_P2P",
	3,
	match_xfire_p2p
};

void register_xfire_p2p(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xfire_p2p, mod_map);
}

