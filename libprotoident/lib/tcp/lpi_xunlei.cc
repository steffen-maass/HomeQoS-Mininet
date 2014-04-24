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
 * $Id: lpi_xunlei.cc 63 2011-02-04 00:59:33Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_xunlei(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/*
        if (match_str_both(data, "\x3c\x00\x00\x00", "\x3c\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x3d\x00\x00\x00", "\x39\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x3d\x00\x00\x00", "\x3a\x00\x00\x00"))
                return true;
        */

        if (match_str_both(data, "\x29\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x36\x00\x00\x00", "\x33\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x36\x00\x00\x00", "\x36\x00\x00\x00"))
                return true;
        if (match_str_either(data, "\x33\x00\x00\x00")) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 87)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 87)
                        return true;
        }

        if (match_str_either(data, "\x36\x00\x00\x00")) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 71)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 71)
                        return true;
        }

        if (match_str_either(data, "\x29\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_xunlei = {
	LPI_PROTO_XUNLEI,
	LPI_CATEGORY_P2P,
	"Xunlei",
	3,
	match_xunlei
};

void register_xunlei(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xunlei, mod_map);
}

