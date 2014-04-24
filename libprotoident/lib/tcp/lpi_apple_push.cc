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
 * $Id: lpi_apple_push.cc 115 2012-02-21 22:51:45Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_apple_push(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule matches the push notifications sent to IOS devices */ 

	if (!match_ssl(data))
		return false;
	
	/* Port 5223 is used for the push notifications */
	if (data->server_port != 5223 && data->client_port != 5223)
		return false;

	/* Too much size variation to write a good set of rules based on
	 * payload sizes, just use this as the fallback option for all
	 * SSL traffic on 5223 that doesn't match something else, e.g.
	 * PSN store */

	return true;
}

static lpi_module_t lpi_apple_push = {
	LPI_PROTO_APPLE_PUSH,
	LPI_CATEGORY_NOTIFICATION,
	"ApplePush",
	5, /* Should be a higher priority than regular SSL, but lower than
	      anything else on port 5223  */
	match_apple_push
};

void register_apple_push(LPIModuleMap *mod_map) {
	register_protocol(&lpi_apple_push, mod_map);
}

