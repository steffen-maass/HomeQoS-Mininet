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
 * $Id: lpi_ssl.cc 107 2011-11-25 00:36:11Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_other_ssl(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_ssl(data))
		return false;
	
	/* Ignore IMAPS and HTTPS, as these are separate protocols */
	if (data->server_port == 993 || data->client_port == 993)
		return false;
	if (data->server_port == 443 || data->client_port == 443)
		return false;

	return true;
}

static lpi_module_t lpi_ssl = {
	LPI_PROTO_SSL,
	LPI_CATEGORY_ENCRYPT,
	"SSL/TLS",
	100, /* Make this lower priority than IMAPS and HTTPS, just in case */
	match_other_ssl
};

void register_ssl(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ssl, mod_map);
}

