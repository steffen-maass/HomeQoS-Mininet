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
 * $Id: lpi_http.cc 61 2011-02-03 00:34:02Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"


static inline bool match_http_response(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (len == 1 && MATCH(payload, 'H', 0x00, 0x00, 0x00))
                return true;
        if (MATCHSTR(payload, "HTTP")) {
                return true;
        }

        /* UNKNOWN seems to be a valid response from some servers, e.g.
         * mini_httpd */
        if (MATCHSTR(payload, "UNKN")) {
                return true;
        }

        return false;
}

static inline bool match_http(lpi_data_t *data, lpi_module_t *mod) {


        /* Need to rule out protocols using HTTP-style commands to do 
         * exchanges. These protocols primarily use GET, rather than other
         * HTTP requests */
        if (!valid_http_port(data)) {
                if (match_str_either(data, "GET "))
                        return false;
        }

        if (match_http_request(data->payload[0], data->payload_len[0])) {
                if (match_http_response(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_http_request(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_file_header(data->payload[1]) &&
                                data->payload_len[0] != 0)
                        return true;
        }

        if (match_http_request(data->payload[1], data->payload_len[1])) {
                if (match_http_response(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_file_header(data->payload[0]) &&
                                data->payload_len[1] != 0)
                        return true;
        }

        /* Allow responses in both directions, even if this is doesn't entirely
         * make sense :/ */
        if (match_http_response(data->payload[0], data->payload_len[0])) {
                if (match_http_response(data->payload[1], data->payload_len[1]))
                        return true;
        }


        return false;


}

static lpi_module_t lpi_http = {
	LPI_PROTO_HTTP,
	LPI_CATEGORY_WEB,
	"HTTP",
	2,	
	match_http
};

void register_http(LPIModuleMap *mod_map) {
	register_protocol(&lpi_http, mod_map);
}

