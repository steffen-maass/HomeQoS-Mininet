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
 * $Id: lpi_jedi.cc 92 2011-09-28 01:36:00Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_jedi(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Citrix have a protocol called JEDI which is used for streaming
	 * in products like GoToMyPC */

	if (match_str_both(data, "JEDI", "JEDI"))
		return true;

	return false;
}

static lpi_module_t lpi_jedi = {
	LPI_PROTO_JEDI,
	LPI_CATEGORY_REMOTE,
	"Citrix_Jedi",
	3,
	match_jedi
};

void register_jedi(LPIModuleMap *mod_map) {
	register_protocol(&lpi_jedi, mod_map);
}

