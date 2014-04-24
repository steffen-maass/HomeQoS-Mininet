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
 * $Id: lpi_pop3.cc 89 2011-06-01 23:23:05Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_pop3(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_chars_either(data, '+', 'O', 'K', ANY))
		return true;
	if (match_chars_either(data, '-', 'E', 'R', 'R'))
		return true;

	if (match_str_either(data, "CAPA")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_str_either(data, "AUTH")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
	return false;

}

static lpi_module_t lpi_pop3 = {
	LPI_PROTO_POP3,
	LPI_CATEGORY_MAIL,
	"POP3",
	2,
	match_pop3
};

void register_pop3(LPIModuleMap *mod_map) {
	register_protocol(&lpi_pop3, mod_map);
}

