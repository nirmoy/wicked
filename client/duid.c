/*
 *	wicked client main commands
 *
 *	Copyright (C) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *              Nirmoy Das <ndas@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/netinfo.h>
#include "duid.h"

static int
ni_do_duid_commit(const char *ifname, ni_opaque_t *duid)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	char *formated_duid = NULL;

	if (!ni_duid_format_hex(&formated_duid, duid))
		return NI_WICKED_RC_ERROR;

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_ERROR;
	if (ni_duid_map_set(map, ifname, formated_duid)) {
		if (ni_duid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_string_free(&formated_duid);
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_create_duid_ll(const char *ifname, const char *hwtype, const char *hwaddr)
{
	ni_opaque_t duid;

	if (ni_string_empty(hwtype)) {
		fprintf(stderr, "missing --hwtype argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_string_empty(hwaddr)) {
		fprintf(stderr, "missing --hwaddr argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_duid_create_ll(&duid, hwtype, hwaddr))
		return ni_do_duid_commit(ifname, &duid);

	return NI_WICKED_RC_ERROR;
}

static int
ni_do_duid_create_duid_llt(const char *ifname, const char *hwtype, const char *hwaddr)
{
	ni_opaque_t duid;

	if (ni_string_empty(hwtype)) {
		fprintf(stderr, "missing --hwtype argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_string_empty(hwaddr)) {
		fprintf(stderr, "missing --hwaddr argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_duid_create_llt(&duid, hwtype, hwaddr))
		return ni_do_duid_commit(ifname, &duid);

	return NI_WICKED_RC_ERROR;
}

static int
ni_do_duid_create_duid_en(const char *ifname, const char *enumber, const char *identifier)
{
	ni_opaque_t duid;

	if (ni_string_empty(enumber)) {
		fprintf(stderr, "missing --enumber argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_string_empty(identifier)) {
		fprintf(stderr, "missing --identifier argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_duid_create_en(&duid, enumber, identifier))
		return ni_do_duid_commit(ifname, &duid);

	return NI_WICKED_RC_ERROR;
}

static int
ni_do_duid_create_duid_uuid_machine_id(const char *ifname)
{
	ni_opaque_t duid;

	if (ni_duid_create_uuid_machine_id(&duid, NULL) == TRUE)
		return ni_do_duid_commit(ifname, &duid);

	return NI_WICKED_RC_ERROR;
}

static int
ni_do_duid_create_duid_uuid_dmi_product_id(const char *ifname)
{
	ni_opaque_t duid;

	if (ni_duid_create_uuid_dmi_product_id(&duid, NULL) == TRUE)
		return ni_do_duid_commit(ifname, &duid);

	return NI_WICKED_RC_ERROR;
}

static int
ni_do_duid_create_duid_uuid(const char *ifname, const char *uuid)
{
	ni_opaque_t duid;

	if (ni_string_empty(uuid)) {
		fprintf(stderr, "missing --identifier argument");
		return NI_WICKED_RC_ERROR;
	}

	if (ni_duid_create_uuid_string(&duid, uuid) == TRUE)
		return ni_do_duid_commit(ifname, &duid);

	return NI_WICKED_RC_ERROR;
}

static int
ni_do_duid_create(const char *caller, const char *ifname, int argc, char **argv)
{
	enum { OPT_HELP = 'h', OPT_HWADDR = 'a',
	       OPT_IDENTIFIER = 'd', OPT_ENTERPRISE = 'n',
		   OPT_UUID = 'u', OPT_HWTYPE = 't',
		   OPT_MACHINEID='m', OPT_DMIPRODUCTID='p'};
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "enumber",	required_argument,		NULL,	OPT_ENTERPRISE	},
		{ "identifier",	required_argument,		NULL,	OPT_IDENTIFIER	},
		{ "uuid",	required_argument,		NULL,	OPT_UUID	},
		{ "machine-id",	no_argument,		NULL,	OPT_MACHINEID	},
		{ "dmi-product-id",	no_argument,		NULL,	OPT_DMIPRODUCTID	},
		{ "hwaddr",	required_argument,		NULL,	OPT_HWADDR	},
		{ "hwtype",	required_argument,		NULL,	OPT_HWTYPE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	const char *duid_type = NULL;
	const char *hwtype = NULL;
	const char *hwaddr = NULL;
	const char *enumber = NULL;
	char *identifier = NULL;
	char *uuid = NULL;
	char *program = NULL;
	ni_bool_t machine_id = FALSE, dmi_product_id = FALSE;

	if (ni_string_printf(&program, "%s", caller  ? caller  : "wicked duid"))
		argv[0] = program;

	optind = 1;
	duid_type = argv[optind++];
	while ((opt = getopt_long(argc, argv, "+ha:d:i:m:n:p:u:t:", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HWADDR:
			hwaddr = optarg;
			break;
		case OPT_HWTYPE:
			if (ni_string_eq(optarg, "help")) {
#if 0
				int hwtype;
				for (hwtype = 0; hwtype < ARPHRD_NONE; ++hwtype) {
					const char *name = ni_duid_hwtype_to_name(hwtype);
					if (name)
						printf("%s\n", name);
				}
				goto cleanup;
#endif
				int i = 0;
				const ni_intmap_t *hwtype = ni_duid_hwtype_map();

				printf("Supported hwtypes are:\n");
				while(hwtype && hwtype[i].name) {
					if (hwtype[i].name)
						printf("%s\n", hwtype[i++].name);
				}
				goto cleanup;
			}
			hwtype = optarg;
			break;
		case OPT_IDENTIFIER:
			identifier = optarg;
			break;
		case OPT_ENTERPRISE:
			enumber = optarg;
			break;
		case OPT_UUID:
			uuid = optarg;
			break;
		case OPT_MACHINEID:
			machine_id = TRUE;
			break;
		case OPT_DMIPRODUCTID:
			dmi_product_id = TRUE;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s [options]\n"
				"\n"
				"Options:\n"
				"create ll --hwaddr <addr> --hwtype <ether|..>\n"
				"create llt --hwaddr <addr> --hwtype <ether|..>\n"
				"create en --enumber <enterprise number> --identifier <data>\n"
				"create uuid --uuid <uuid>\n"
				"create uuid --machine-id\n"
				"create uuid --dmi-product-id\n"
				"\n", program);
			goto cleanup;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "%s: invalid arguments\n", program);
		goto usage;
	}

	if (ni_string_eq(duid_type, "ll")) {
		status = ni_do_duid_create_duid_ll(ifname, hwtype, hwaddr);
	} else
	if (ni_string_eq(duid_type, "llt")) {
		status = ni_do_duid_create_duid_llt(ifname, hwtype, hwaddr);
	} else
	if (ni_string_eq(duid_type, "en")) {
		status = ni_do_duid_create_duid_en(ifname, enumber, identifier);
	} else
	if (ni_string_eq(duid_type, "uuid")) {
		if (machine_id && dmi_product_id)
			goto usage;

		if (machine_id)
			status = ni_do_duid_create_duid_uuid_machine_id(ifname);
		else if (dmi_product_id)
			status = ni_do_duid_create_duid_uuid_dmi_product_id(ifname);
		else
			status = ni_do_duid_create_duid_uuid(ifname, uuid);
	} else {
		fprintf(stderr, "Unsupported duid type %s \n", duid_type);
	}

	if(status != NI_WICKED_RC_SUCCESS)
		goto usage;
cleanup:
	ni_string_free(&program);
	return status;
}


static int
ni_do_duid_dump(const char *command, int argc, char **argv)
{
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	ni_var_t *var;

	switch (argc) {
	case 1:
		break;
	default:
		fprintf(stderr, "Usage: %s\n", command);
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_SUCCESS;
	if (ni_duid_map_to_vars(map, &vars)) {
		unsigned int i;

		for (i = 0, var = vars.data; i < vars.count; ++i, ++var) {
			printf("%s\t%s\n", var->name ? var->name : "default", var->value);
		}
		ni_var_array_destroy(&vars);
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_get(const char *command, int argc, char **argv)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *ifname = NULL;
	const char *duid = NULL;

	switch (argc) {
	case 2:
		ifname = argv[--argc];
	case 1:
		break;
	default:
		fprintf(stderr, "Usage: %s [ifname|default]\n", command);
		goto cleanup;
	}

	if (ni_string_eq(ifname, "default")) {
		ifname = NULL;
	} else
	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", command,
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_NO_DEVICE;
	if (ni_duid_map_get_duid(map, ifname, &duid)) {
		printf("%s\t%s\n", ifname ? ifname : "default", duid);
		status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_set(const char *command, int argc, char **argv)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *ifname = NULL;
	const char *duid = NULL;
	ni_opaque_t raw;

	switch (argc) {
	case 3:
		duid   = argv[--argc];
		ifname = argv[--argc];
		break;
	case 2:
		duid   = argv[--argc];
		break;
	default:
		fprintf(stderr, "Usage: %s [ifname|default] <duid>\n", command);
		goto cleanup;
	}

	if (ni_string_eq(ifname, "default")) {
		ifname = NULL;
	} else
	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", command,
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	if (ni_string_empty(duid) || !ni_duid_parse_hex(&raw, duid)) {
		fprintf(stderr, "%s: unable to parse duid hex string\n", command);
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_ERROR;
	if (ni_duid_map_set(map, ifname, duid)) {
		if (ni_duid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_del(const char *command, int argc, char **argv)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *ifname = NULL;

	switch (argc) {
	case 2:
		ifname = argv[--argc];
	case 1:
		break;
	default:
		fprintf(stderr, "Usage: %s [ifname|default]\n", command);
		goto cleanup;
	}

	if (ni_string_eq(ifname, "default")) {
		ifname = NULL;
	} else
	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", command,
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	if (ni_duid_map_del(map, ifname)) {
		if (ni_duid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

int
ni_do_duid(const char *caller, int argc, char **argv)
{
	enum { OPT_HELP = 'h', OPT_IFNAME = 'i' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "ifname",	required_argument,	NULL,	OPT_IFNAME	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	const char *ifname = NULL;
	char *program = NULL;
	char *command = NULL;
	const char *cmd;

	if (ni_string_printf(&program, "%s %s", caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "duid"))
		argv[0] = program;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hi:", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_IFNAME:
			if (!ni_netdev_name_is_valid(optarg)) {
				fprintf(stderr, "%s: invalid interface name '%s'\n", program,
						ni_print_suspect(optarg, ni_string_len(optarg)));
				goto cleanup;
			}
			ifname = optarg;
			break;

		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s <command>\n"
				"\n"
				"Options:\n"
				"  --help, -h          show this help text and exit.\n"
				"  --ifname|-i <name>  use on non-standard per-device duid\n"
				"\n"
				"Commands:\n"
				"  help\n"
				"  dump\n"
				"  get [options]\n"
				"  del [options]\n"
				"  set [options] <duid>\n"
				"  create [options] <args>\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "%s: missing command\n", program);
		goto usage;
	}

	cmd = argv[optind];
	ni_string_printf(&command, "%s %s", program, cmd);

	if (ni_string_eq(cmd, "help")) {
		status = NI_WICKED_RC_SUCCESS;
		goto usage;
	} else
	if (ni_string_eq(cmd, "dump")) {
		status = ni_do_duid_dump(command, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "get")) {
		status = ni_do_duid_get (command, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "set")) {
		status = ni_do_duid_set (command, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "del")) {
		status = ni_do_duid_del (command, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "create")) {
		status = ni_do_duid_create (command, ifname, argc - optind, argv + optind);
	} else {
		fprintf(stderr, "%s: unsupported command %s\n", program, cmd);
		goto usage;
	}

cleanup:
	ni_string_free(&command);
	ni_string_free(&program);
	return status;
}

