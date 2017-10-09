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

typedef struct ni_ethtool_offload {
	ni_tristate_t	rx_csum;
	ni_tristate_t	tx_csum;
	ni_tristate_t	scatter_gather;
	ni_tristate_t	tso;
	ni_tristate_t	ufo;
	ni_tristate_t	gso;
	ni_tristate_t	gro;
	ni_tristate_t	lro;
	ni_tristate_t	rxvlan;
	ni_tristate_t	txvlan;
	ni_tristate_t	ntuple;
	ni_tristate_t	rxhash;
} ni_ethtool_offload_t;

#define NI_ETHTOOL_EEE_DEFAULT		-1U

typedef struct ni_ethtool_eee {
	ni_tristate_t	supported;

	struct {
		ni_tristate_t	enabled;
		ni_tristate_t	active;
	} status;
	struct {
		unsigned int	supported;
		unsigned int	advertised;
		unsigned int	lp_advertised;
	} speed;
	struct {
		ni_tristate_t	enabled;
		unsigned int	timer;
	} tx_lpi;
} ni_ethtool_eee_t;

#define NI_ETHTOOL_CHANNELS_DEFAULT		-1U

typedef struct ni_ethtool_channels {
	ni_tristate_t	supported;
	unsigned int	tx;
	unsigned int	rx;
	unsigned int	other;
	unsigned int	combined;
} ni_ethtool_channels_t;

#define NI_ETHTOOL_RING_DEFAULT		-1U

typedef struct ni_ethtool_ring {
	ni_tristate_t	supported;
	unsigned int	tx;
	unsigned int	rx;
	unsigned int	rx_jumbo;
	unsigned int	rx_mini;
} ni_ethtool_ring_t;

#define NI_ETHTOOL_COALESCE_DEFAULT		-1U

typedef struct ni_ethtool_coalesce {
	ni_tristate_t	supported;

	ni_tristate_t   adaptive_tx;
	ni_tristate_t   adaptive_rx;

	unsigned int	pkt_rate_low;
	unsigned int	pkt_rate_high;

	unsigned int	sample_interval;
	unsigned int	stats_block_usecs;

	unsigned int	rx_usecs;
	unsigned int	rx_usecs_irq;
	unsigned int	rx_usecs_low;
	unsigned int	rx_usecs_high;

	unsigned int	rx_frames;
	unsigned int	rx_frames_irq;
	unsigned int	rx_frames_low;
	unsigned int	rx_frames_high;

	unsigned int	tx_usecs;
	unsigned int	tx_usecs_irq;
	unsigned int	tx_usecs_low;
	unsigned int	tx_usecs_high;

	unsigned int	tx_frames;
	unsigned int	tx_frames_irq;
	unsigned int	tx_frames_low;
	unsigned int	tx_frames_high;
} ni_ethtool_coalesce_t;

struct ni_ethtool {
	unsigned int			supported;

	ni_ethtool_driver_info_t *	driver_info;
	ni_ethtool_link_settings_t *	link_settings;

	ni_ethtool_pause_t *		pause;
	ni_ethtool_offload_t	*offload;
	ni_ethtool_eee_t	*eee;
	ni_ethtool_ring_t	*ring;
	ni_ethtool_coalesce_t	*coalesce;
	ni_ethtool_channels_t	*channels;
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
