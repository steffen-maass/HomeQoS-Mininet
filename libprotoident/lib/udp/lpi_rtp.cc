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
 * $Id: lpi_rtp.cc 107 2011-11-25 00:36:11Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_rtp_payload(uint32_t payload, uint32_t len, 
		uint32_t other_len) {

	if (len < 32)
		return false;

	/* Be stricter about packet length when looking at one-way flows */
	if (other_len == 0) {
		if (len != 32 && len != 92 && len != 172)
			return false;
	}

	if (MATCH(payload, 0x80, ANY, ANY, ANY))
		return true;
	if (MATCH(payload, 0x90, ANY, ANY, ANY))
		return true;

	return false;

}

static inline bool match_stun_response(uint32_t payload, uint32_t len) {

	/* Many VOIP phones use STUN for NAT traversal, so the response to
	 * outgoing RDP is often a STUN packet */

	if (!MATCH(payload, 0x00, 0x01, 0x00, 0x08))
		return false;
	if (len != 28)
		return false;

	return true;

}

static inline bool match_rtp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Watch out for one-way DNS... */
	if (data->client_port == 53 || data->client_port == 53) {
		if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
			return false;
	}

	if (match_rtp_payload(data->payload[0], data->payload_len[0], 
			data->payload_len[1])) {
		if (match_stun_response(data->payload[1], data->payload_len[1]))
			return true;
		if (match_rtp_payload(data->payload[1], data->payload_len[1], 
				data->payload_len[0])) {
			uint32_t a = ntohl(data->payload[0]) & 0xffff0000;
			uint32_t b = ntohl(data->payload[1]) & 0xffff0000;

			if (a != b)
				return false;
			return true;
		}
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_rtp_payload(data->payload[1], data->payload_len[1], 
			data->payload_len[0])) {
		if (match_stun_response(data->payload[0], data->payload_len[0]))
			return true;
		if (data->payload_len[0] == 0)
			return true;
	}
	return false;
}

static lpi_module_t lpi_rtp = {
	LPI_PROTO_UDP_RTP,
	LPI_CATEGORY_VOIP,
	"RTP",
	13,
	match_rtp
};

void register_rtp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rtp, mod_map);
}

