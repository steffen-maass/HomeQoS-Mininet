/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 * 	Aaron Murrihy
 * 	Donald Neal
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
 * $Id: libprotoident.cc 133 2012-11-04 21:03:53Z salcock $
 */

#define __STDC_FORMAT_MACROS
#define __STDC_LIMIT_MACROS

#include <stdio.h>
#include <assert.h>
//#include <libtrace.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include "libprotoident.h"
#include "proto_manager.h"


bool init_called = false;
LPIModuleMap TCP_protocols;
LPIModuleMap UDP_protocols;

lpi_module_t *lpi_icmp = NULL;
lpi_module_t *lpi_unsupported = NULL;
lpi_module_t *lpi_unknown_tcp = NULL;
lpi_module_t *lpi_unknown_udp = NULL;

static LPINameMap lpi_names;

int lpi_init_library() {

	if (init_called) {
		fprintf(stderr, "WARNING: lpi_init_library has already been called\n");
		return 0;
	}
	
	if (register_tcp_protocols(&TCP_protocols) == -1) 
		return -1;
	
	if (register_udp_protocols(&UDP_protocols) == -1) 
		return -1;

	init_other_protocols(&lpi_names);

	register_names(&TCP_protocols, &lpi_names);
	register_names(&UDP_protocols, &lpi_names);

	init_called = true;

	if (TCP_protocols.empty() && UDP_protocols.empty()) {
		fprintf(stderr, "WARNING: No protocol modules loaded\n");
		return -1;
	}


	return 0;

}

void lpi_free_library() {

	free_protocols(&TCP_protocols);
	free_protocols(&UDP_protocols);

	init_called = false;
}

void lpi_init_data(lpi_data_t *data) {

	data->payload[0] = 0;
	data->payload[1] = 0;
	data->seqno[0] = 0;
	data->seqno[1] = 0;
	data->observed[0] = 0;
	data->observed[1] = 0;
	data->server_port = 0;
	data->client_port = 0;
	data->trans_proto = 0;
	data->payload_len[0] = 0;
	data->payload_len[1] = 0;
	data->ips[0] = 0;
	data->ips[1] = 0;

}

static lpi_module_t *test_protocol_list(LPIModuleList *ml, lpi_data_t *data) {

	LPIModuleList::iterator l_it;
	
	/* Turns out naively looping through the modules is quicker
	 * than trying to do intelligent stuff with threads. Most
	 * callbacks complete very quickly so threading overhead is a
	 * major problem */
	for (l_it = ml->begin(); l_it != ml->end(); l_it ++) {
		lpi_module_t *module = *l_it;

		/* To save time, I'm going to break on the first successful
		 * match. A threaded version would wait for all the modules
		 * to run, storing all successful results in a list of some
		 * sort and selecting an appropriate result from there.
		 */

		if (module->lpi_callback(data, module)) 
			return module;
		
	}

	return NULL;
}
static lpi_module_t *guess_protocol(LPIModuleMap *modmap, lpi_data_t *data) {

	lpi_module_t *proto = NULL;

	LPIModuleMap::iterator m_it;

	/* Deal with each priority in turn - want to match higher priority
	 * rules first. 
	 */

	for (m_it = modmap->begin(); m_it != modmap->end(); m_it ++) {
		LPIModuleList *ml = m_it->second;
		
		proto = test_protocol_list(ml, data);

		if (proto != NULL)
			break;
	}

	return proto;

}

lpi_module_t *lpi_guess_protocol(lpi_data_t *data) {

	lpi_module_t *p = NULL;

	if (!init_called) {
		fprintf(stderr, "lpi_init_library was never called - cannot guess the protocol\n");
		return NULL;
	}

	switch(data->trans_proto) {
		case TRACE_IPPROTO_ICMP:
			return lpi_icmp;
		case TRACE_IPPROTO_TCP:
			p = guess_protocol(&TCP_protocols, data);
			if (p == NULL)
				p = lpi_unknown_tcp;
			return p;

		case TRACE_IPPROTO_UDP:
			p = guess_protocol(&UDP_protocols, data);
			if (p == NULL)
				p = lpi_unknown_udp;
			return p;
		default:
			return lpi_unsupported;
	}


	return p;
}
	
lpi_category_t lpi_categorise(lpi_module_t *module) {

	if (module == NULL)
		return LPI_CATEGORY_NO_CATEGORY;

	return module->category;

}

const char *lpi_print_category(lpi_category_t category) {

	switch(category) {
		case LPI_CATEGORY_WEB:
			return "Web";
		case LPI_CATEGORY_MAIL:
			return "Mail";
		case LPI_CATEGORY_CHAT:
			return "Chat";
		case LPI_CATEGORY_P2P:
			return "P2P";
		case LPI_CATEGORY_P2P_STRUCTURE:
			return "P2P_Structure";
		case LPI_CATEGORY_KEY_EXCHANGE:
			return "Key_Exchange";
		case LPI_CATEGORY_ECOMMERCE:
			return "ECommerce";
		case LPI_CATEGORY_GAMING:
			return "Gaming";
		case LPI_CATEGORY_ENCRYPT:
			return "Encryption";
		case LPI_CATEGORY_MONITORING:
			return "Measurement";
		case LPI_CATEGORY_NEWS:
			return "News";
		case LPI_CATEGORY_MALWARE:
			return "Malware";
		case LPI_CATEGORY_SECURITY:
			return "Security";
		case LPI_CATEGORY_ANTISPAM:
			return "Antispam";
		case LPI_CATEGORY_VOIP:
			return "VOIP";
		case LPI_CATEGORY_TUNNELLING:
			return "Tunnelling";
		case LPI_CATEGORY_NAT:
			return "NAT_Traversal";
		case LPI_CATEGORY_STREAMING:
			return "Streaming";
		case LPI_CATEGORY_SERVICES:
			return "Services";
		case LPI_CATEGORY_DATABASES:
			return "Databases";
		case LPI_CATEGORY_FILES:
			return "File_Transfer";
		case LPI_CATEGORY_REMOTE:
			return "Remote_Access";
		case LPI_CATEGORY_TELCO:
			return "Telco_Services";
		case LPI_CATEGORY_P2PTV:
			return "P2PTV";
		case LPI_CATEGORY_RCS:
			return "Revision_Control";
		case LPI_CATEGORY_LOGGING:
			return "Logging";
		case LPI_CATEGORY_PRINTING:
			return "Printing";
		case LPI_CATEGORY_TRANSLATION:
			return "Translation";
		case LPI_CATEGORY_CDN:
			return "CDN";
		case LPI_CATEGORY_CLOUD:
			return "Cloud";
		case LPI_CATEGORY_NOTIFICATION:
			return "Notification";
		case LPI_CATEGORY_SERIALISATION:
			return "Serialisation";
		case LPI_CATEGORY_BROADCAST:
			return "Broadcast";
		case LPI_CATEGORY_LOCATION:
			return "Location";
		case LPI_CATEGORY_ICMP:
			return "ICMP";
		case LPI_CATEGORY_MIXED:
			return "Mixed";
		case LPI_CATEGORY_NOPAYLOAD:
			return "No_Payload";
		case LPI_CATEGORY_UNKNOWN:
			return "Unknown";
		case LPI_CATEGORY_UNSUPPORTED:
			return "Unsupported";
		case LPI_CATEGORY_NO_CATEGORY:
			return "Uncategorised";
	}

	return "Invalid_Category";

}
			
const char *lpi_print(lpi_protocol_t proto) {

	LPINameMap::iterator it;

	it = lpi_names.find(proto);

	if (it == lpi_names.end()) {
		return "NULL";
	}	
	return (it->second);
	
}

bool lpi_is_protocol_inactive(lpi_protocol_t proto) {

	LPINameMap::iterator it;

	it = lpi_names.find(proto);

	if (it == lpi_names.end()) {
		return true;
	}	
	return false;

}

const char* lpi_shim_guess_protocol(unsigned int client_payload,
				    unsigned int server_payload,
				    unsigned int client_ip,
				    unsigned int server_ip,
				    unsigned int client_port,
				    unsigned int server_port,
				    unsigned int client_payload_length,
				    unsigned int server_payload_length,
				    char protocol)
{
    lpi_data_t data;
    lpi_module_t* module;

    lpi_init_data(&data);

    data.payload[0]     = client_payload;
    data.client_port    = client_port;
    data.payload_len[0] = client_payload_length;
    data.ips[0]         = client_ip;

    data.payload[1]     = server_payload;
    data.server_port    = server_port;
    data.payload_len[1] = server_payload_length;
    data.ips[1]         = server_ip;

    data.trans_proto    = protocol;

    module = lpi_guess_protocol(&data);

    return (lpi_print_category(lpi_categorise(module)));    
}
