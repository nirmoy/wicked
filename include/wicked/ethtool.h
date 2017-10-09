/*
 *	ethtool support
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
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 *		Olaf Kirch <okir@suse.de>
 */
#ifndef WICKED_ETHTOOL_H
#define WICKED_ETHTOOL_H

#include <wicked/types.h>

typedef struct ni_ethtool_driver_info {
	char *			driver;
	char *			version;
	char *			bus_info;
	char *			fw_version;
	char *			erom_version;
	struct {
		unsigned int	n_priv_flags;
		unsigned int	n_stats;
		unsigned int	testinfo_len;
		unsigned int	eedump_len;
		unsigned int	regdump_len;
	} supports;
} ni_ethtool_driver_info_t;

typedef struct ni_ethtool_link_settings {
	ni_tristate_t			autoneg;
	unsigned int			speed;
	uint8_t				duplex;
	uint8_t				port;
} ni_ethtool_link_settings_t;

typedef struct ni_ethtool_pause {
	ni_tristate_t			autoneg;
	ni_tristate_t			rx;
	ni_tristate_t			tx;
} ni_ethtool_pause_t;

struct ni_ethtool {
	unsigned int			supported;

	ni_ethtool_driver_info_t *	driver_info;
	ni_ethtool_link_settings_t *	link_settings;

	ni_ethtool_pause_t *		pause;
};

extern ni_ethtool_t *			ni_ethtool_new(void);
extern void				ni_ethtool_free(ni_ethtool_t *);

/* TODO -> ni_system_ethtool_refresh/setup */
extern ni_bool_t			ni_ethtool_refresh(ni_netdev_t *);
extern int				ni_ethtool_setup(ni_netdev_t *, const ni_ethtool_t *);

extern ni_ethtool_driver_info_t *	ni_ethtool_driver_info_new(void);
extern void				ni_ethtool_driver_info_free(ni_ethtool_driver_info_t *);

extern ni_ethtool_link_settings_t *	ni_ethtool_link_settings_new(void);
extern void				ni_ethtool_link_settings_free(ni_ethtool_link_settings_t *);

extern ni_ethtool_pause_t *		ni_ethtool_pause_new(void);
extern void				ni_ethtool_pause_free(ni_ethtool_pause_t *);

#endif /* WICKED_ETHTOOL_H */
