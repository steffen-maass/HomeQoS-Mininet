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
 * $Id: lpi_pptp.cc 63 2011-02-04 00:59:33Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_pptp_payload(uint32_t payload, uint32_t len) {

        if (len != 156)
                return false;

        if (!MATCH(payload, 0x00, 0x9c, 0x00, 0x01))
                return false;

        return true;

}


static inline bool match_pptp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_pptp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_pptp_payload(data->payload[1], data->payload_len[1]))
		return false;
	return true;

}

static lpi_module_t lpi_pptp = {
	LPI_PROTO_PPTP,
	LPI_CATEGORY_TUNNELLING,
	"PPTP",
	3,
	match_pptp
};

void register_pptp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_pptp, mod_map);
}

