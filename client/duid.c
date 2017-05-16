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
#include "duid.h"


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
	} else {
		fprintf(stderr, "%s: unsupported command %s\n", program, cmd);
		goto usage;
	}

cleanup:
	ni_string_free(&program);
	return status;
}

