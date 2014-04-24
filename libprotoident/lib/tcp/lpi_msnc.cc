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
 * $Id: lpi_msnc.cc 63 2011-02-04 00:59:33Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_msnc(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* http://msnpiki.msnfanatic.com/index.php/MSNC:File_Transfer#Direct_connection:_Handshake */

        /* MSNC sends the length as a separate packet before the data. To
         * confirm MSNC, you have to look at the second packet sent by the
         * connecting host. It should begin with 'foo'. */

        if (match_str_both(data, "\x30\x00\x00\x00", "\x04\x00\x00\x00")) {
                if (data->payload_len[0] == 4 && data->payload_len[1] == 4)
                        return true;
        }
        if (match_str_both(data, "\x10\x00\x00\x00", "\x04\x00\x00\x00")) {
                if (MATCH(data->payload[0], 0x04, 0x00, 0x00, 0x00)) {
                        if (data->payload_len[0] == 4)
                                return true;
                }
                if (MATCH(data->payload[1], 0x04, 0x00, 0x00, 0x00)) {
                        if (data->payload_len[1] == 4)
                                return true;
                }
        }

	return false;
}

static lpi_module_t lpi_msnc = {
	LPI_PROTO_MSNC,
	LPI_CATEGORY_FILES,
	"MSNC",
	3,
	match_msnc
};

void register_msnc(LPIModuleMap *mod_map) {
	register_protocol(&lpi_msnc, mod_map);
}

