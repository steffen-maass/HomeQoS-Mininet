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
 * $Id: lpi_zynga.cc 122 2012-03-02 03:49:27Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_zynga(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_both(data, "pres", "3 se"))
		return true;
	if (match_str_both(data, "pres", "4 se"))
		return true;
	if (match_str_both(data, "imsg", "4 se"))
		return true;

	/* Flash facebook games */
	if (match_str_both(data, "<msg", "<?xm")) {
		if (data->server_port == 9339 || data->client_port == 9339)
			return true;
	}

	return false;
}

static lpi_module_t lpi_zynga = {
	LPI_PROTO_ZYNGA,
	LPI_CATEGORY_GAMING,
	"Zynga",
	3,
	match_zynga
};

void register_zynga(LPIModuleMap *mod_map) {
	register_protocol(&lpi_zynga, mod_map);
}

