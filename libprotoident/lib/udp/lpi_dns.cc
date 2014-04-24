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
 * $Id: lpi_dns.cc 76 2011-04-08 04:45:36Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_dns_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* As loath as I am to do this, we probably shouldn't allow any DNS
	 * on ports other than 53 */
	if (data->server_port != 53 && data->client_port != 53)
		return false;

	if (match_dns(data))
		return true;

	return false;
}

static lpi_module_t lpi_dns_udp = {
	LPI_PROTO_UDP_DNS,
	LPI_CATEGORY_SERVICES,
	"DNS",
	10,	/* Not a high certainty */
	match_dns_udp
};

void register_dns_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dns_udp, mod_map);
}

