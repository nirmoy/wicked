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

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/netinfo.h>
#include "duid.h"

static int
ni_do_duid_dump(const char *command, const char *ifname, int argc, char **argv)
{
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	ni_var_t *var;

	if (argc != 1 || ifname) {
		fprintf(stderr, "%s: invalid arguments\n", command);
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
ni_do_duid_get(const char *command, const char *ifname, int argc, char **argv)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *duid = NULL;

	if (argc != 1) {
		fprintf(stderr, "%s: invalid arguments\n", command);
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
ni_do_duid_set(const char *command, const char *ifname, int argc, char **argv)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *duid = NULL;
	ni_opaque_t raw;

	if (argc != 2) {
		fprintf(stderr, "%s: invalid arguments\n", command);
		goto cleanup;
	}

	duid = argv[1];
	if (ni_string_empty(duid)) {
		fprintf(stderr, "%s: missing duid argument\n", command);
		goto cleanup;
	} else
	if (!ni_duid_parse_hex(&raw, duid)) {
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
ni_do_duid_del(const char *command, const char *ifname, int argc, char **argv)
{
	int status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;

	if (argc != 1) {
		fprintf(stderr, "%s: invalid arguments\n", command);
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
		status = ni_do_duid_dump(command, ifname, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "get")) {
		status = ni_do_duid_get (command, ifname, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "set")) {
		status = ni_do_duid_set (command, ifname, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "del")) {
		status = ni_do_duid_del (command, ifname, argc - optind, argv + optind);
	} else {
		fprintf(stderr, "%s: unsupported command %s\n", program, cmd);
		goto usage;
	}

cleanup:
	ni_string_free(&command);
	ni_string_free(&program);
	return status;
}

