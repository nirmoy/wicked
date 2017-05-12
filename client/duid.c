/*
 *	This command line utility provides an interface to the network
 *	configuration/information facilities.
 *
 *	Copyright (C) 2010-2017 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <mcheck.h>
#include <limits.h>
#include <fcntl.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/resolver.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>

#include "duid.h"

#define CONFIG_DEFAULT_DUID_FILE	"duid.xml"

void
usage(void)
{
	fprintf(stderr, 
			"wicked duid [options] <ifname ...>|all [args]\n"
			"\nSupported duid options:\n"
			"get <ifname ...>|all>\n"
			"	Show existing duid for given interface\n"
			"set <ifname ...>|all> <duid>\n"
			"	Set duid for a given interface\n"
			"create <ifname ...>|all> <duid-ll|duid-llt|duid-uuid> <args>\n"
			"	Create a duid of given type and given interface\n");
	exit(1);
}

xml_node_t *
ni_fetch_duid_node_by_attr(const char *attr)
{
	xml_document_t *duid_doc;
	xml_node_t *ifnode;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", 
			ni_config_storedir(),
			CONFIG_DEFAULT_DUID_FILE);
    duid_doc = xml_document_read(path);
	if (duid_doc) {
	for (ifnode = duid_doc->root->children; ifnode; ifnode = ifnode->next) {
				const char *devicenode = xml_node_get_attr(ifnode, "device");
				if ((!devicenode && ni_string_eq(attr, "default")) ||
						ni_string_eq(attr, devicenode))
					return ifnode;
			}
	}
	return NULL;
}

static int
ni_create_duid_node(char *ifname, const char* duid)
{
	xml_document_t *duid_doc;
	xml_node_t *ifnode;
	char path[PATH_MAX];
	ni_bool_t node_exist = FALSE;

	snprintf(path, sizeof(path), "%s/%s", 
			ni_config_storedir(),
			CONFIG_DEFAULT_DUID_FILE);
	if (!ni_file_exists(path)) { /* if !path create the file TODO permissions ? */
		creat(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	}

    duid_doc = xml_document_read(path);
	if (duid_doc) { /* empty file */
		if (!duid_doc->root->children) {
			xml_node_t* node =
				xml_node_new_element("uuid", duid_doc->root, duid);
			xml_node_add_attr(node, "device", ifname);
		} else {
			for (ifnode = duid_doc->root->children; ifnode; ifnode = ifnode->next) {
				const char *devicenode = xml_node_get_attr(ifnode, "device");
				if ((!devicenode && ni_string_eq(ifname, "default")) ||
						ni_string_eq(ifname, devicenode)) {
					xml_node_set_cdata(ifnode, duid);
					node_exist = TRUE;
				} 
			}
			if (!node_exist) {
				xml_node_t* node = 
					xml_node_new_element("uuid", duid_doc->root, duid);
				xml_node_add_attr(node, "device", ifname);
			}
		}
		xml_document_write(duid_doc, path);
		xml_document_free(duid_doc);
		return 0;
	} else {
		ni_error("Failed to read %s", path);
		return 1;
	}
	return 1; //Should never reach here
}

static int
ni_do_duid_get(ni_string_array_t *ifnames)
{
	xml_document_t *duid_doc;
	xml_node_t *ifnode;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", 
			ni_config_storedir(),
			CONFIG_DEFAULT_DUID_FILE);


     	duid_doc = xml_document_read(path);
		if (duid_doc) {
			for (ifnode = duid_doc->root->children; ifnode; ifnode = ifnode->next) {
				const char *devicenode = xml_node_get_attr(ifnode, "device");
				if (ifnames->count) {
					if ((devicenode ? ni_string_array_index(ifnames, devicenode):
									ni_string_array_index(ifnames, "default"))== -1)
						continue;
				}
				xml_node_print(ifnode, stdout);
			}
			xml_document_free(duid_doc);
			return 0;
		}
		return 1;
}

static int
ni_do_duid_set(ni_string_array_t *ifnames, char *duid)
{
	xml_document_t *duid_doc;
	xml_node_t *ifnode;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", 
			ni_config_storedir(),
			CONFIG_DEFAULT_DUID_FILE);

     	duid_doc = xml_document_read(path);
		if (duid_doc) {
			for (ifnode = duid_doc->root->children; ifnode; ifnode = ifnode->next) {
				const char *devicenode = xml_node_get_attr(ifnode, "device");
				if (ifnames->count) {
					if ((devicenode ? ni_string_array_index(ifnames, devicenode):
									ni_string_array_index(ifnames, "default"))== -1)
						continue;
				}
				ni_create_duid_node(devicenode ? devicenode:"default", duid);
			}
			xml_document_free(duid_doc);
			return 0;
		}

		return 1;
}

static int
ni_do_duid_create_duid_llt(ni_netdev_t *dev, char *ifname)
{
	ni_opaque_t duid;

	if (dev) {
		ni_duid_init_llt(&duid, dev->link.hwaddr.type,
			dev->link.hwaddr.data, dev->link.hwaddr.len);
		ni_create_duid_node(ifname, ni_print_hex(duid.data, duid.len));
		return 0;
	}
	return -1;
}

static int
ni_do_duid_create_duid_ll(ni_netdev_t *dev, char *ifname)
{
	ni_opaque_t duid;
	
	if (dev) {
		ni_duid_init_ll(&duid, dev->link.hwaddr.type,
				dev->link.hwaddr.data, dev->link.hwaddr.len);
		ni_create_duid_node(ifname, ni_print_hex(duid.data, duid.len));
		return 0;
	}
	return 1;
}

int
ni_do_duid_create_duid_en(ni_netdev_t *dev, char *ifname, 
		uint32_t enumber, char *identifier)
{
	ni_opaque_t enid;
	ni_opaque_t duid;
    
	enid.len = ni_parse_hex_data(identifier, enid.data, sizeof(duid.data), ":");
#if 0
    if ((ssize_t)enid.len <= 0 || enid.len > NI_DUID_DATA_LEN - sizeof(uint32_t))
    	return FALSE;
#endif
	ni_duid_init_en(&duid, enumber, enid.data, enid.len);
	return ni_create_duid_node(ifname, ni_print_hex(duid.data, duid.len));
}

int
ni_do_duid_create_duid_uuid(ni_netdev_t *dev, char *ifname, char *str_uuid)
{
	ni_uuid_t uuid;
	ni_opaque_t duid;
	
	ni_parse_hex_data(str_uuid, uuid.octets, sizeof(uuid.octets), "");
	ni_duid_init_uuid(&duid, &uuid);
	return ni_create_duid_node(ifname, ni_print_hex(duid.data, duid.len));
}

int 
ni_do_duid_create(int argc, char **argv)
{
	int status = 0;
	int optind = 2, c;
	char *duid_type;
	char *ifname[IFNAMSIZ] = {0};
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_bool_t all = FALSE;
	ni_netdev_t *dev = NULL, *tmp_dev = NULL;
	ni_init(argv[0]);
	ni_netconfig_t *nc = ni_global_state_handle(1);

	for (c = optind; c < argc; ++c) {
		char *ifname = argv[c];
		if (ni_string_eq(ifname, "all")) {
			ni_string_array_destroy(&ifnames);
			all = TRUE;
			break;
		}
		if (ni_string_startswith(ifname, "duid"))
			break;
		if (ni_string_array_index(&ifnames, ifname) == -1)
			ni_string_array_append(&ifnames, ifname);
	}
	// TODO if all==TRUE fill ifnames 
	optind += !all ? (c - 2) : 1; //todo verify
	if (optind >= argc)
		usage();
	
	duid_type = argv[optind]; optind++;
	if (all) {
		for(tmp_dev = ni_netconfig_devlist(nc); tmp_dev; tmp_dev = tmp_dev->next) {
			if (ni_string_array_index(&ifnames, ifname) == -1)
				ni_string_array_append(&ifnames, tmp_dev->name);
		}
	}

	for (c = 0; c < ifnames.count; c++) {
		ni_string_array_get(&ifnames, c, ifname);
		if (ni_string_eq(ifname[0], "default")) {
			for(tmp_dev = ni_netconfig_devlist(nc); tmp_dev; tmp_dev = tmp_dev->next) {
				switch(tmp_dev->link.hwaddr.type) {
					case ARPHRD_ETHER:
					case ARPHRD_IEEE802:
					case ARPHRD_INFINIBAND:
						if (tmp_dev->link.hwaddr.len)
							dev = tmp_dev;
				}
			}
		} else {
			dev = ni_netdev_by_name(nc, ifname[0]);
		}

		if (dev) {
			if(ni_string_eq(duid_type, "duid-llt")) {
				ni_do_duid_create_duid_llt(dev, ifname[0]);
			} else 
			if(ni_string_eq(duid_type, "duid-ll")){
				ni_do_duid_create_duid_ll(dev, ifname[0]);
			} else
			if (ni_string_eq(duid_type, "duid-en")) {
				uint32_t enumber;
		
				if (argc <= optind + 1)
					usage();

				ni_parse_uint(argv[optind++], &enumber, 0);
				ni_do_duid_create_duid_en(dev, ifname[0], enumber, argv[optind]);
			} else
			if (ni_string_eq(duid_type, "duid-uuid")) {
				printf("%s\n", ifname[0]);

				if(optind >= argc)
					usage();

				ni_do_duid_create_duid_uuid(dev, ifname[0], argv[optind]);
			} else {
				fprintf(stderr, "Unsupported duid type %s %s\n", duid_type, ni_config_storedir());
				usage();
			}
		} else {
			ni_warn("%s: device doesn't exist", ifname[0]);
		}
	}
	//TODO
	return status;
}

int
ni_do_duid(int argc, char **argv)
{
	const char *opt_cmd;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	int status;
	int optind = 1, c;
	ni_bool_t         all = FALSE;

	opt_cmd = argv[optind];

	if (ni_string_eq(opt_cmd, "create")) {
		return ni_do_duid_create(argc, argv);
	}
	for (c = optind; c < argc; ++c) {
		char *ifname = argv[c];

		if (ni_string_eq(ifname, "all")) {
			ni_string_array_destroy(&ifnames);
			all = TRUE;
			break;
		}

		if (ni_string_array_index(&ifnames, ifname) == -1)
			ni_string_array_append(&ifnames, ifname);
	}
	if (!all && ifnames.count == 0)
		usage();

	optind += !all ? (c - 2) : 2; //todo verify
	if (ni_string_eq(opt_cmd, "get")) {
		ni_do_duid_get(&ifnames);
	} else
	if (!strncmp(opt_cmd, "set", 3)) {
		if (optind >= argc)
			usage();
		ni_do_duid_set(&ifnames, argv[optind]);
	} else {
		fprintf(stderr, "Unsupported command %s\n", opt_cmd);
		return 1; //TODO usage
	}
	status = NI_WICKED_ST_OK;

cleanup:
	ni_string_array_destroy(&ifnames);
	return status;
}
