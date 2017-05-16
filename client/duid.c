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
ni_do_duid_get(const char *caller, int argc, char **argv)
{
	enum { OPT_HELP = 'h', OPT_IFNAME = 'i' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "ifname",	required_argument,	NULL,	OPT_IFNAME	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *ifname = NULL;
	const char *duid = NULL;
	char *program = NULL;

	if (ni_string_printf(&program, "%s %s", caller  ? caller  : "wicked duid",
						argv[0] ? argv[0] : "get"))
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
				"  %s [options]\n"
				"\n"
				"Options:\n"
				"  --help, -h      show this help text and exit.\n"
				"  --ifname <name> show non-standard per-device duid\n"
				"\n", program);
			goto cleanup;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "%s: invalid arguments\n", program);
		goto usage;
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
	ni_string_free(&program);
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_set(const char *caller, int argc, char **argv)
{
	ni_duid_map_t *map;
	const char *ifname = NULL;
	ni_opaque_t raw;
	int status;

	if (argc != 3 || ni_string_empty(argv[2]))
		return NI_WICKED_RC_USAGE;

	if (!ni_duid_parse_hex(&raw, argv[2]))
		return NI_WICKED_RC_USAGE;

	if (!ni_string_eq(argv[1], "default"))
		ifname = argv[1];

	if (!(map = ni_duid_map_load(NULL)))
		return NI_WICKED_RC_ERROR;

	status = NI_WICKED_RC_ERROR;
	if (ni_duid_map_set(map, ifname, argv[2])) {
		if (ni_duid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_del(const char *caller, int argc, char **argv)
{
	ni_duid_map_t *map;
	const char *ifname = NULL;
	int status;

	if (argc != 2)
		return NI_WICKED_RC_USAGE;

	if (!ni_string_eq(argv[1], "default"))
		ifname = argv[1];

	if (!(map = ni_duid_map_load(NULL)))
		return NI_WICKED_RC_ERROR;

	status = NI_WICKED_RC_ERROR;
	if (ni_duid_map_del(map, ifname)) {
		if (ni_duid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

	ni_duid_map_free(map);
	return status;
}

int
ni_do_duid(const char *caller, int argc, char **argv)
{
	enum { OPT_HELP = 'h' };
	static struct option	options[] = {
		{ "help",	no_argument,	NULL,	'h'	},
		{ NULL,		no_argument,	NULL,	0	}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	char *program = NULL;
	const char *cmd;

	if (ni_string_printf(&program, "%s %s", caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "test"))
		argv[0] = program;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s <command>\n"
				"\n"
				"Options:\n"
				"  --help, -h      show this help text and exit.\n"
				"\n"
				"Commands:\n"
				"  get [default|ifname]\n"
				"  set <default|ifname>\n"
				"  del <default|ifname>\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "%s: missing command\n", program);
		goto usage;
	}

	cmd = argv[optind];
	if (ni_string_eq(cmd, "help")) {
		status = NI_WICKED_RC_SUCCESS;
		goto usage;
	} else
	if (ni_string_eq(cmd, "get")) {
		status = ni_do_duid_get (program, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "set")) {
		status = ni_do_duid_set (program, argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "del")) {
		status = ni_do_duid_del (program, argc - optind, argv + optind);
	} else {
		fprintf(stderr, "%s: unsupported command %s\n", program, cmd);
		goto usage;
	}

cleanup:
	ni_string_free(&program);
	return status;
}

