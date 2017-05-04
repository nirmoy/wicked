/*
 *	This command line utility provides an interface to the network
 *	configuration/information facilities.
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

//#define CONFIG_DEFAULT_DUID_FILE	"duid.xml"
#define CONFIG_DEFAULT_DUID_FILE	"./test_duid.xml"

int 
ni_do_duid_create(int argc, char **argv)
{
	int status = 0;
	int optind = 1, c;
	const char *opt_cmd;
	xml_document_t *duid_doc;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_bool_t         all = FALSE;
	char *duid_type, *hw_type, *identifier, *enterprise, *time;

	opt_cmd = argv[optind];
	
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
	
	optind += all ? (c-2) : 1; //todo verify
	duid_type = argv[optind];
	
	if (!strncmp(duid_type, "duid-llt", 3)) {
	} else
	if (!strncmp(duid_type, "duid-ll", 3)) {
	} else
	if (!strncmp(duid_type, "duid-en", 3)) {
	} else
	if (!strncmp(duid_type, "duid-uuid", 3)) {
	} else {
		fprintf(stderr, "Unsupported command %s\n", opt_cmd);
	}
	


//TODO
	return status;
}

int
ni_do_duid(int argc, char **argv)
{
	const char *opt_cmd;
	xml_document_t *duid_doc;
	xml_node_t *ifnode;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	char path[PATH_MAX];
	int status;
	int optind = 1, c;
	ni_bool_t         all = FALSE;

	opt_cmd = argv[optind];

	if (!strncmp(opt_cmd, "create", 5)) {
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
	
	optind += !all ? (c-2) : 1; //todo verify
	printf("%d\n", optind);
	snprintf(path, sizeof(path), "%s/%s", 
			//ni_config_storedir(),
			".",
			CONFIG_DEFAULT_DUID_FILE);

	if (!strncmp(opt_cmd, "get", 3)) {
     	duid_doc = xml_document_read(path);
		if (duid_doc) {
			for (ifnode = duid_doc->root->children; ifnode; ifnode = ifnode->next) {
				const char *devicenode = xml_node_get_attr(ifnode, "device");
				if (!all) {
					if ((devicenode ? ni_string_array_index(&ifnames, devicenode):
									ni_string_array_index(&ifnames, "default"))== -1)
						continue;
				}
				xml_node_print(ifnode, stdout);
			}
		}
	} else
	if (!strncmp(opt_cmd, "set", 3)) {
     	duid_doc = xml_document_read(path);
		if (duid_doc) {
			for (ifnode = duid_doc->root->children; ifnode; ifnode = ifnode->next) {
				const char *devicenode = xml_node_get_attr(ifnode, "device");
				if (!all) {
					if ((devicenode ? ni_string_array_index(&ifnames, devicenode):
									ni_string_array_index(&ifnames, "default"))== -1)
						continue;
				}
				xml_node_set_cdata(ifnode, argv[optind]);
				xml_node_print(ifnode, stdout);
			}
			//TODO store the doc + cleanup
		}

	} else {
		fprintf(stderr, "Unsupported command %s\n", opt_cmd);
		return 1; //TODO usage
	}
	status = NI_WICKED_ST_OK;

cleanup:
	ni_string_array_destroy(&ifnames);
	return status;
}
