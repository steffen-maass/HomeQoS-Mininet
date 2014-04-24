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
 * $Id: lpi_traceroute.cc 105 2011-11-16 21:28:42Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_ea_traceroute(uint32_t payload, uint32_t len) {

	if (len != 42)
		return false;
	if (!MATCH(payload, 'P', 'a', 't', 'h'))
		return false;
	return true;

}

static inline bool match_planetlab_traceroute(uint32_t payload, uint32_t len) {
	if (len != 82)
		return false;
	if (!MATCH(payload, '@', 'A', 'B', 'C'))
		return false;
	return true;
}

static inline bool match_traceroute(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* The iVMG people put payload in their traceroute packets that
         * we can easily identify */

        if (match_str_either(data, "iVMG"))
                return true;

	/* Spammy traceroute observed coming from EA servers */
	if (match_ea_traceroute(data->payload[0], data->payload_len[0])) {
		if (data->payload_len[1] == 0)
			return true;
	}
	
	if (match_ea_traceroute(data->payload[1], data->payload_len[1])) {
		if (data->payload_len[0] == 0)
			return true;
	}

	/* This seems to be a traceroute sent from planetlab nodes */
	if (match_planetlab_traceroute(data->payload[0], data->payload_len[0]))
	{
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_planetlab_traceroute(data->payload[1], data->payload_len[1]))
	{
		if (data->payload_len[0] == 0)
			return true;
	}


	if (data->payload_len[0] == 0) {
		if (!MATCH(data->payload[1], ANY, ANY, 0x00, 0x00))
			return false;
		if (data->payload_len[1] != 16 && data->payload_len[1] != 8)
			return false;
		if (data->server_port != 33435 && data->client_port != 33435)
			return false;
		return true;
	}

	if (data->payload_len[1] == 0) {
		if (!MATCH(data->payload[0], ANY, ANY, 0x00, 0x00))
			return false;
		if (data->payload_len[0] != 16 && data->payload_len[1] != 8)
			return false;
		if (data->server_port != 33435 && data->client_port != 33435)
			return false;
		return true;
	}
	return false;
}

static lpi_module_t lpi_traceroute = {
	LPI_PROTO_UDP_TRACEROUTE,
	LPI_CATEGORY_MONITORING,
	"Traceroute_UDP",
	2,
	match_traceroute
};

void register_traceroute(LPIModuleMap *mod_map) {
	register_protocol(&lpi_traceroute, mod_map);
}

