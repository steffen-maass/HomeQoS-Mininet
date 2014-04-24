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
 * $Id: lpi_psn_store.cc 115 2012-02-21 22:51:45Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_psn_store(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule matches the SSL exchanges used by the Playstation
	 * Store */

	if (!match_ssl(data))
		return false;
	
	/* All PSN SSL traffic is on port 5223 */
	if (data->server_port != 5223 && data->client_port != 5223)
		return false;

	if (data->payload_len[0] == 66 && data->payload_len[1] == 1085)
		return true;
	if (data->payload_len[1] == 66 && data->payload_len[0] == 1085)
		return true;
	
	return false;
}

static lpi_module_t lpi_psn_store = {
	LPI_PROTO_PSN_STORE,
	LPI_CATEGORY_GAMING,
	"PSNStore",
	2, /* Should be a higher priority than regular SSL */
	match_psn_store
};

void register_psn_store(LPIModuleMap *mod_map) {
	register_protocol(&lpi_psn_store, mod_map);
}

