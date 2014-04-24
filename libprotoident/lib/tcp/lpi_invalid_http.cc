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
 * $Id: lpi_invalid_http.cc 62 2011-02-03 04:37:32Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_invalid_http(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This function is for identifying web servers that are not 
         * following the HTTP spec properly.
         *
         * For flows where the client is not doing HTTP properly, see
         * match_web_junk().
         */

        /* HTTP servers that appear to respond with raw HTML */
        if (match_str_either(data, "GET ")) {
                if (match_chars_either(data, '<', 'H', 'T', 'M'))
                        return true;
                if (match_chars_either(data, '<', 'h', 't', 'm'))
                        return true;
                if (match_chars_either(data, '<', 'h', '1', '>'))
                        return true;
                if (match_chars_either(data, '<', 't', 'i', 't'))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_invalid_http = {
	LPI_PROTO_INVALID_HTTP,
	LPI_CATEGORY_WEB,
	"Invalid_HTTP",
	200,
	match_invalid_http
};

void register_invalid_http(LPIModuleMap *mod_map) {
	register_protocol(&lpi_invalid_http, mod_map);
}

