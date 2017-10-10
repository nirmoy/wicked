/*
 *	ethtool handling routines
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <errno.h>

#include <wicked/util.h>
#include <wicked/ethtool.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "kernel.h"

/*
 * support mask to not repeat ioctl
 * calls that returned EOPNOTSUPP.
 */
enum {
	NI_ETHTOOL_SUPP_DRIVER_INFO,
	NI_ETHTOOL_SUPP_LINK_LEGACY,
	NI_ETHTOOL_SUPP_LINK_SETTINGS,
	NI_ETHTOOL_SUPP_FEATURES,
	NI_ETHTOOL_SUPP_PAUSE,

	NI_ETHTOOL_SUPPORT_MAX
};

static inline ni_bool_t
ni_ethtool_supported(const ni_ethtool_t *ethtool, unsigned int flag)
{
	return ethtool ? ethtool->supported & NI_BIT(flag) : FALSE;
}

static inline ni_bool_t
ni_ethtool_set_supported(ni_ethtool_t *ethtool, unsigned int flag, ni_bool_t enable)
{
	if (ethtool) {
		if (enable)
			ethtool->supported |= NI_BIT(flag);
		else
			ethtool->supported &= ~NI_BIT(flag);
		return TRUE;
	}
	return FALSE;
}

/*
 * ethtool cmd error logging utilities
 */
typedef struct ni_ethtool_cmd_info {
	int		cmd;
	const char *	name;
} ni_ethtool_cmd_info_t;

static int
ni_ethtool_call(const char *ifname, const ni_ethtool_cmd_info_t *ioc, void *evp, const char *flag)
{
	int ret, err;

	ret = __ni_ethtool(ifname, ioc->cmd, evp);
	if (ret < 0) {
		err = errno;
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ethtool %s%s failed: %m", ifname, ioc->name, flag ? flag : "");
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool %s%s failed: %m", ifname, ioc->name, flag ? flag : "");
		errno = err;
	}
	return ret;
}

/*
 * driver-info (GDRVINFO)
 */
void
ni_ethtool_driver_info_free(ni_ethtool_driver_info_t *info)
{
	if (info) {
		ni_string_free(&info->driver);
		ni_string_free(&info->version);
		ni_string_free(&info->fw_version);
		ni_string_free(&info->bus_info);
		ni_string_free(&info->erom_version);
		free(info);
	}
}

ni_ethtool_driver_info_t *
ni_ethtool_driver_info_new(void)
{
	ni_ethtool_driver_info_t *info;

	info = calloc(1, sizeof(*info));
	return info;
}

static int
ni_ethtool_get_driver_info(const char *ifname, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GDRVINFO = {
		ETHTOOL_GDRVINFO,      "get driver-info"
	};
	struct ethtool_drvinfo drv_info;
	ni_ethtool_driver_info_t *info;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_DRIVER_INFO))
		return -1;

	ni_ethtool_driver_info_free(ethtool->driver_info);
	ethtool->driver_info = NULL;

	memset(&drv_info, 0, sizeof(drv_info));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GDRVINFO, &drv_info, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_DRIVER_INFO,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0)
		return ret;

	if (!(info = ni_ethtool_driver_info_new()))
		return -1;

	drv_info.driver[sizeof(drv_info.driver)-1] = '\0';
	if (!ni_string_empty(drv_info.driver))
		ni_string_dup(&info->driver, drv_info.driver);

	drv_info.version[sizeof(drv_info.version)-1] = '\0';
	if (!ni_string_empty(drv_info.version))
		ni_string_dup(&info->version, drv_info.version);

	drv_info.fw_version[sizeof(drv_info.fw_version)-1] = '\0';
	if (!ni_string_empty(drv_info.fw_version))
		ni_string_dup(&info->fw_version, drv_info.fw_version);

	drv_info.bus_info[sizeof(drv_info.bus_info)-1] = '\0';
	if (!ni_string_empty(drv_info.bus_info))
		ni_string_dup(&info->bus_info, drv_info.bus_info);

	drv_info.erom_version[sizeof(drv_info.erom_version)-1] = '\0';
	if (!ni_string_empty(drv_info.erom_version))
		ni_string_dup(&info->erom_version, drv_info.erom_version);

	info->supports.n_stats		= drv_info.n_stats;
	info->supports.n_priv_flags	= drv_info.n_priv_flags;
	info->supports.testinfo_len	= drv_info.testinfo_len;
	info->supports.eedump_len	= drv_info.eedump_len;
	info->supports.regdump_len	= drv_info.regdump_len;

	ethtool->driver_info = info;

	return 0;
}


/*
 * new and legacy link-settings
 */
static const ni_intmap_t	ni_ethternet_duplex_names[] = {
	{ "half",		NI_ETHTOOL_DUPLEX_HALF		},
	{ "full",		NI_ETHTOOL_DUPLEX_FULL		},

	{ NULL,			NI_ETHTOOL_DUPLEX_UNKNOWN	}
};

ni_bool_t
ni_ethtool_duplex_map_name(const char *name, ni_ethtool_duplex_t *mode)
{
	return ni_parse_uint_mapped(name, ni_ethternet_duplex_names, mode) == 0;
}

const char *
ni_ethtool_duplex_map_mode(ni_ethtool_duplex_t mode)
{
	return ni_format_uint_mapped(mode, ni_ethternet_duplex_names);
}

static const ni_intmap_t	ni_ethternet_port_type_names[] = {
	{ "tp",			NI_ETHTOOL_PORT_TP		},
	{ "aui",		NI_ETHTOOL_PORT_AUI		},
	{ "bnc",		NI_ETHTOOL_PORT_BNC		},
	{ "mii",		NI_ETHTOOL_PORT_MII		},
	{ "fibre",		NI_ETHTOOL_PORT_FIBRE		},
	{ "da",			NI_ETHTOOL_PORT_DA		},
	{ "none",		NI_ETHTOOL_PORT_NONE		},

	{ NULL,			NI_ETHTOOL_PORT_OTHER		}
};

ni_bool_t
ni_ethtool_port_map_type(const char *name, ni_ethtool_port_type_t *type)
{
	return ni_parse_uint_mapped(name, ni_ethternet_port_type_names, type) == 0;
}

const char *
ni_ethtool_port_map_name(ni_ethtool_port_type_t type)
{
	return ni_format_uint_mapped(type, ni_ethternet_port_type_names);
}

void
ni_ethtool_link_settings_free(ni_ethtool_link_settings_t *settings)
{
	if (settings) {
		free(settings);
	}
}

ni_ethtool_link_settings_t *
ni_ethtool_link_settings_new(void)
{
	ni_ethtool_link_settings_t *settings;

	settings = calloc(1, sizeof(*settings));
	if (settings) {
		settings->autoneg = NI_TRISTATE_DEFAULT;
		settings->speed	  = NI_ETHTOOL_SPEED_UNKNOWN;
		settings->duplex  = NI_ETHTOOL_DUPLEX_UNKNOWN;
		settings->port    = NI_ETHTOOL_PORT_OTHER;
	}
	return settings;
}

/*
 * legacy link-settings (GSET,SSET)
 */
static int
ni_ethtool_get_legacy_settings(const char *ifname, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSET	= {
		ETHTOOL_GSET,          "get settings"
	};
	struct ethtool_cmd settings;
	ni_ethtool_link_settings_t *link;
	int ret;

	ni_trace("%s(%s) TODO", __func__, ifname);

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_LINK_LEGACY))
		return -1;

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = NULL;

	memset(&settings, 0, sizeof(settings));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GSET, &settings, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_LINK_LEGACY,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0)
		return ret;

	if (!(link = ni_ethtool_link_settings_new()))
		return -1;

	link->autoneg	= settings.autoneg == AUTONEG_ENABLE;
	link->speed     = ethtool_cmd_speed(&settings);
	link->duplex    = settings.duplex;
	link->port      = settings.port;

	ethtool->link_settings = link;
	return 0;
}

static int
ni_ethtool_set_legacy_settings(const char *ifname, ni_ethtool_t *ethtool,
		const ni_ethtool_link_settings_t *cfg)
{
#if 0
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SSET	= {
		ETHTOOL_SSET,		"set settings"
	};
#endif
	(void)ifname;
	(void)ethtool;
	(void)cfg;

	ni_trace("%s(%s) TODO", __func__, ifname);

	return 0;
}

/*
 * new link-settings (GLINKSETTINGS,SLINKSETTINGS)
 */
static int
ni_ethtool_get_link_settings(const char *ifname, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GLINKSETINGS = {
		ETHTOOL_GLINKSETTINGS,	"get link-settings"
	};
	struct ethtool_link_settings settings;
	ni_ethtool_link_settings_t *link;
	int ret;

	ni_trace("%s(%s)", __func__, ifname);

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_LINK_SETTINGS))
		return ni_ethtool_get_legacy_settings(ifname, ethtool);

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = NULL;

	memset(&settings, 0, sizeof(settings));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GLINKSETINGS, &settings, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_LINK_SETTINGS,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0) {
		if (errno == EOPNOTSUPP)
			return ni_ethtool_get_legacy_settings(ifname, ethtool);
		return ret;
	}

	if (!(link = ni_ethtool_link_settings_new()))
		return -1;

	link->autoneg	= settings.autoneg == AUTONEG_ENABLE;
	link->speed     = settings.speed;
	link->duplex    = settings.duplex;
	link->port      = settings.port;

	ethtool->link_settings = link;
	return 0;

}

static int
ni_ethtool_set_link_settings(const char *ifname, ni_ethtool_t *ethtool,
			const ni_ethtool_link_settings_t *cfg)
{
#if 0
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SLINKSETINGS = {
		ETHTOOL_SLINKSETTINGS,	"set link-settings"
	};
#endif
	ni_trace("%s(%s)", __func__, ifname);

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_LINK_SETTINGS))
		return ni_ethtool_set_legacy_settings(ifname, ethtool, cfg);

	return 0;
}


/*
 * offload and other features
 */
typedef enum {
	NI_ETHTOOL_FEATURE_SG,
	NI_ETHTOOL_FEATURE_IP_CSUM,
	NI_ETHTOOL_FEATURE_HW_CSUM,
	NI_ETHTOOL_FEATURE_IPV6_CSUM,
	NI_ETHTOOL_FEATURE_HIGHDMA,
	NI_ETHTOOL_FEATURE_FRAGLIST,
	NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX,
	NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX,
	NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_FILTER,
	NI_ETHTOOL_FEATURE_HW_VLAN_STAG_TX,
	NI_ETHTOOL_FEATURE_HW_VLAN_STAG_RX,
	NI_ETHTOOL_FEATURE_HW_VLAN_STAG_FILTER,
	NI_ETHTOOL_FEATURE_VLAN_CHALLENGED,
	NI_ETHTOOL_FEATURE_GSO,
	NI_ETHTOOL_FEATURE_LLTX,
	NI_ETHTOOL_FEATURE_NETNS_LOCAL,
	NI_ETHTOOL_FEATURE_GRO,
	NI_ETHTOOL_FEATURE_LRO,
	NI_ETHTOOL_FEATURE_TSO,
	NI_ETHTOOL_FEATURE_UFO,
	NI_ETHTOOL_FEATURE_GSO_ROBUST,
	NI_ETHTOOL_FEATURE_TSO_ECN,
	NI_ETHTOOL_FEATURE_TSO6,
	NI_ETHTOOL_FEATURE_FSO,
	NI_ETHTOOL_FEATURE_GSO_GRE,
	NI_ETHTOOL_FEATURE_GSO_IPIP,
	NI_ETHTOOL_FEATURE_GSO_SIT,
	NI_ETHTOOL_FEATURE_GSO_UDP_TUNNEL,
	NI_ETHTOOL_FEATURE_FCOE_CRC,
	NI_ETHTOOL_FEATURE_SCTP_CSUM,
	NI_ETHTOOL_FEATURE_FCOE_MTU,
	NI_ETHTOOL_FEATURE_NTUPLE,
	NI_ETHTOOL_FEATURE_RXHASH,
	NI_ETHTOOL_FEATURE_RXCSUM,
	NI_ETHTOOL_FEATURE_NOCACHE_COPY,
	NI_ETHTOOL_FEATURE_LOOPBACK,
	NI_ETHTOOL_FEATURE_RXFCS,
	NI_ETHTOOL_FEATURE_RXALL,
	NI_ETHTOOL_FEATURE_HW_L2FW_DOFFLOAD,
	NI_ETHTOOL_FEATURE_BUSY_POLL,
	NI_ETHTOOL_FEATURE_HW_TC,

	NI_ETHTOOL_FEATURE_UNKNOWN = -1U
} ni_ethtool_feature_id_t;

static const ni_intmap_t		ni_ethtool_feature_name_map[] = {
	/* known feature name and alias map, -1U and allocated name for unknown features */
/*l,w*/	{ "scatter-gather",			NI_ETHTOOL_FEATURE_SG			},
/*s*/	{ "sg",					NI_ETHTOOL_FEATURE_SG			},
/*k*/	{ "tx-scatter-gather",			NI_ETHTOOL_FEATURE_SG			},
	{ "tx-checksum-ipv4",			NI_ETHTOOL_FEATURE_IP_CSUM		},
/*w*/	{ "tx-csum",				NI_ETHTOOL_FEATURE_HW_CSUM		},
/*k*/	{ "tx-checksum-ip-generic",		NI_ETHTOOL_FEATURE_HW_CSUM		},
/*l*/	{ "tx-checksumming",			NI_ETHTOOL_FEATURE_HW_CSUM		},
/*s*/	{ "tx",					NI_ETHTOOL_FEATURE_HW_CSUM		},
	{ "tx-checksum-ipv6",			NI_ETHTOOL_FEATURE_IPV6_CSUM		},
	{ "highdma",				NI_ETHTOOL_FEATURE_HIGHDMA		},
	{ "tx-scatter-gather-fraglist",		NI_ETHTOOL_FEATURE_FRAGLIST		},
/*s,w*/	{ "txvlan",				NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX	},
/*k*/	{ "tx-vlan-hw-insert",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX	},
/*l*/	{ "tx-vlan-offload",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX	},
/*s,w*/	{ "rxvlan",				NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX	},
/*k*/	{ "rx-vlan-hw-parse",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX	},
/*l*/	{ "rx-vlan-offload",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX	},
	{ "rx-vlan-filter",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_FILTER	},
	{ "tx-vlan-stag-hw-insert",		NI_ETHTOOL_FEATURE_HW_VLAN_STAG_TX	},
	{ "rx-vlan-stag-hw-parse",		NI_ETHTOOL_FEATURE_HW_VLAN_STAG_RX	},
	{ "rx-vlan-stag-filter",		NI_ETHTOOL_FEATURE_HW_VLAN_STAG_FILTER	},
	{ "vlan-challenged",			NI_ETHTOOL_FEATURE_VLAN_CHALLENGED	},
/*s,w*/	{ "gso",				NI_ETHTOOL_FEATURE_GSO			},
/*k*/	{ "tx-generic-segmentation",		NI_ETHTOOL_FEATURE_GSO			},
/*l*/	{ "generic-segmentation-offload",	NI_ETHTOOL_FEATURE_GSO			},
	{ "tx-lockless",			NI_ETHTOOL_FEATURE_LLTX			},
	{ "netns-local",			NI_ETHTOOL_FEATURE_NETNS_LOCAL		},
/*s,w*/	{ "gro",				NI_ETHTOOL_FEATURE_GRO			},
/*k*/	{ "rx-gro",				NI_ETHTOOL_FEATURE_GRO			},
/*l*/	{ "generic-receive-offload",		NI_ETHTOOL_FEATURE_GRO			},
/*s,w*/	{ "lro",				NI_ETHTOOL_FEATURE_LRO			},
/*k*/	{ "rx-lro",				NI_ETHTOOL_FEATURE_LRO			},
/*l*/	{ "large-receive-offload",		NI_ETHTOOL_FEATURE_LRO			},
/*s,w*/	{ "tso",				NI_ETHTOOL_FEATURE_TSO			},
/*k*/	{ "tx-tcp-segmentation",		NI_ETHTOOL_FEATURE_TSO			},
/*l*/	{ "tcp-segmentation-offload",		NI_ETHTOOL_FEATURE_TSO			},
/*s,w*/	{ "ufo",				NI_ETHTOOL_FEATURE_UFO			},
/*k*/	{ "tx-udp-fragmentation",		NI_ETHTOOL_FEATURE_UFO			},
/*l*/	{ "udp-fragmentation-offload",		NI_ETHTOOL_FEATURE_UFO			},
	{ "tx-gso-robust",			NI_ETHTOOL_FEATURE_GSO_ROBUST		},
	{ "tx-tcp-ecn-segmentation",		NI_ETHTOOL_FEATURE_TSO_ECN		},
	{ "tx-tcp6-segmentation",		NI_ETHTOOL_FEATURE_TSO6			},
	{ "tx-fcoe-segmentation",		NI_ETHTOOL_FEATURE_FSO			},
	{ "tx-gre-segmentation",		NI_ETHTOOL_FEATURE_GSO_GRE		},
	{ "tx-ipip-segmentation",		NI_ETHTOOL_FEATURE_GSO_IPIP		},
	{ "tx-sit-segmentation",		NI_ETHTOOL_FEATURE_GSO_SIT		},
	{ "tx-udp_tnl-segmentation",		NI_ETHTOOL_FEATURE_GSO_UDP_TUNNEL	},
	{ "tx-checksum-fcoe-crc",		NI_ETHTOOL_FEATURE_FCOE_CRC		},
	{ "tx-checksum-sctp",			NI_ETHTOOL_FEATURE_SCTP_CSUM		},
	{ "fcoe-mtu",				NI_ETHTOOL_FEATURE_FCOE_MTU		},
/*s,w*/	{ "ntuple",				NI_ETHTOOL_FEATURE_NTUPLE		},
/*k*/	{ "rx-ntuple-filter",			NI_ETHTOOL_FEATURE_NTUPLE		},
/*l*/	{ "ntuple-filters",			NI_ETHTOOL_FEATURE_NTUPLE		},
/*s,w*/	{ "rxhash",				NI_ETHTOOL_FEATURE_RXHASH		},
/*k*/	{ "rx-hashing",				NI_ETHTOOL_FEATURE_RXHASH		},
/*l*/	{ "receive-hashing",			NI_ETHTOOL_FEATURE_RXHASH		},
/*w*/	{ "rx-csum",				NI_ETHTOOL_FEATURE_RXCSUM		},
/*k*/	{ "rx-checksum",			NI_ETHTOOL_FEATURE_RXCSUM		},
/*l*/	{ "rx-checksumming",			NI_ETHTOOL_FEATURE_RXCSUM		},
/*s*/	{ "rx",					NI_ETHTOOL_FEATURE_RXCSUM		},
	{ "tx-nocache-copy",			NI_ETHTOOL_FEATURE_NOCACHE_COPY		},
	{ "loopback",				NI_ETHTOOL_FEATURE_LOOPBACK		},
	{ "rx-fcs",				NI_ETHTOOL_FEATURE_RXFCS		},
	{ "rx-all",				NI_ETHTOOL_FEATURE_RXALL		},
	{ "l2-fwd-offload",			NI_ETHTOOL_FEATURE_HW_L2FW_DOFFLOAD,	},
	{ "busy-poll",				NI_ETHTOOL_FEATURE_BUSY_POLL		},
	{ "hw-tc-offload",			NI_ETHTOOL_FEATURE_HW_TC		},

	{ NULL,					NI_ETHTOOL_FEATURE_UNKNOWN		}
};

static const char *
ni_ethtool_feature_map_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_feature_name_map);
}

static ni_bool_t
ni_ethtool_feature_map_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_feature_name_map, type) == 0;
}

static void
ni_ethtool_feature_free(ni_ethtool_feature_t *feature)
{
	if (feature) {
		if (feature->map.value == NI_ETHTOOL_FEATURE_UNKNOWN)
			free((char *)feature->map.name);
		feature->map.name = NULL;
		free(feature);
	}
}

static ni_ethtool_feature_t *
ni_ethtool_feature_new(const char *name, unsigned int index)
{
	ni_ethtool_feature_t *feature;
	char *copy = NULL;

	/* ensure every feature has a name   */
	if (ni_string_empty(name))
		return NULL;

	feature = calloc(1, sizeof(*feature));
	if (!feature)
		return NULL;

	/* set kernel index (-1U on undef)   */
	feature->index = index;

	/* set id when it's a known feature  */
	if (ni_ethtool_feature_map_type(name, &feature->map.value) &&
	    (feature->map.name = ni_ethtool_feature_map_name(feature->map.value)))
		return feature;

	/* or deep copy unknown feature name */
	feature->map.value = NI_ETHTOOL_FEATURE_UNKNOWN;
	if (ni_string_dup(&copy, name) && (feature->map.name = copy))
		return feature;

	ni_ethtool_feature_free(feature);
	return NULL;
}

static void
ni_ethtool_features_destroy(ni_ethtool_features_t *features)
{
	if (features) {
		while (features->count--)
			ni_ethtool_feature_free(features->features[features->count]);
		free(features->features);
		features->features = NULL;
	}
}

void
ni_ethtool_features_free(ni_ethtool_features_t *features)
{
	if (features) {
		ni_ethtool_features_destroy(features);
		free(features);
	}
}

ni_ethtool_features_t *
ni_ethtool_features_new(void)
{
	ni_ethtool_features_t *features;

	features = calloc(1, sizeof(*features));
	return features;
}

#define NI_ETHTOOL_FEATURE_ARRAY_CHUNK		16

static inline ni_bool_t
ni_ethtool_features_realloc(ni_ethtool_features_t *features, unsigned int newsize)
{
	ni_ethtool_feature_t **newdata;
	unsigned int i;

	if (!features || (UINT_MAX - NI_ETHTOOL_FEATURE_ARRAY_CHUNK) <= newsize)
		return FALSE;

	newsize = (newsize + NI_ETHTOOL_FEATURE_ARRAY_CHUNK);
	newdata = realloc(features->features, newsize * sizeof(*newdata));
	if (!newdata)
		return FALSE;

	features->features = newdata;
	for (i = features->count; i < newsize; ++i)
		features->features[i] = NULL;
	return TRUE;
}

static ni_bool_t
ni_ethtool_features_add(ni_ethtool_features_t *features, ni_ethtool_feature_t *feature)
{
	if (!features || !feature)
		return FALSE;

	if ((features->count % NI_ETHTOOL_FEATURE_ARRAY_CHUNK) == 0 &&
	    !ni_ethtool_features_realloc(features, features->count))
		return FALSE;

	features->features[features->count++] = feature;
	return TRUE;
}

static ni_ethtool_feature_t *
ni_ethtool_features_get(ni_ethtool_features_t *features, const char *name)
{
	ni_ethtool_feature_t *feature;
	unsigned int i, known;

	if (!features || ni_string_empty(name))
		return NULL;

	if (ni_ethtool_feature_map_type(name, &known)) {
		for (i = 0; i < features->count; ++i) {
			if (!(feature = features->features[i]))
				continue;

			if (known == feature->map.value)
				return feature;
		}
	} else {
		for (i = 0; i < features->count; ++i) {
			if (!(feature = features->features[i]))
				continue;

			if (ni_string_eq(name, feature->map.name))
				return feature;
		}
	}
	return NULL;
}

ni_ethtool_feature_t *
ni_ethtool_features_set(ni_ethtool_features_t *features, const char *name, ni_ethtool_feature_value_t value)
{
	ni_ethtool_feature_t *feature;

	if ((feature = ni_ethtool_features_get(features, name))) {
		feature->value = value;
		return feature;
	} else
	if ((feature = ni_ethtool_feature_new(name, -1U))) {
		feature->value = value;
		if (ni_ethtool_features_add(features, feature))
			return feature;
		ni_ethtool_feature_free(feature);
	}
	return NULL;
}

static unsigned int
ni_ethtool_get_feature_count(const char *ifname)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSSET_INFO = {
		ETHTOOL_GSSET_INFO,	"get features count"
	};
	struct {
		struct ethtool_sset_info hdr;
		uint32_t buf[1];
	} sset_info;
	unsigned int count = 0;

	memset(&sset_info, 0, sizeof(sset_info));
	sset_info.hdr.sset_mask = 1ULL << ETH_SS_FEATURES;
	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GSSET_INFO, &sset_info, NULL) < 0)
		count = -1U;
	else
	if (sset_info.hdr.sset_mask == (1ULL << ETH_SS_FEATURES))
		count = sset_info.hdr.data[0];

	return count;
}

static struct ethtool_gstrings *
ni_ethtool_get_feature_strings(const char *ifname, unsigned int count)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSTRINGS = {
		ETHTOOL_GSTRINGS, "get feature names"
	};
	struct ethtool_gstrings *gstrings;
	unsigned int i;

	if (!count || count == -1U)
		return NULL;

	gstrings = calloc(1, sizeof(*gstrings) + count * ETH_GSTRING_LEN);
	if (!gstrings) {
		ni_warn("%s: unable to allocate %u ethtool feature gstrings", ifname, count);
		return NULL;
	}

	gstrings->string_set = ETH_SS_FEATURES;
	gstrings->len = count;
	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GSTRINGS, gstrings, NULL) < 0) {
		int err = errno;
		free(gstrings);
		errno = err;
		return NULL;
	}

	/* ensure the feature name strings are null-terminated */
	for (i = 0; i < gstrings->len; i++)
		gstrings->data[(i + 1) * ETH_GSTRING_LEN - 1] = 0;
	return gstrings;
}

#define ni_ethtool_get_feature_blocks(n)	(((n) + 31U) / 32U)

static struct ethtool_gfeatures *
ni_ethtool_get_feature_values(const char *ifname, unsigned int count)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GFEATURES = {
		ETHTOOL_GFEATURES, "get feature values"
	};
	struct ethtool_gfeatures *gfeatures;
	unsigned int blocks;

	if (!count || count == -1U)
		return NULL;

	blocks = ni_ethtool_get_feature_blocks(count);
	gfeatures = calloc(1, sizeof(*gfeatures) + blocks * sizeof(gfeatures->features[0]));
	if (!gfeatures) {
		ni_warn("%s: unable to allocate %u ethtool feature values", ifname, count);
		return NULL;
	}

	gfeatures->size = blocks;
	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GFEATURES, gfeatures, NULL) < 0) {
		int err = errno;
		free(gfeatures);
		errno = err;
		return NULL;
	}

	return gfeatures;
}

static int
ni_ethtool_get_features_init(const char *ifname, ni_ethtool_features_t *features)
{
	struct ethtool_gfeatures *gfeatures;
	struct ethtool_gstrings *gstrings;
	ni_ethtool_feature_t *feature;
	unsigned int i;

	ni_assert(features != NULL);
	features->total = ni_ethtool_get_feature_count(ifname);
	if (features->total == 0 || features->total == -1U)
		return -1;

	gstrings = ni_ethtool_get_feature_strings(ifname, features->total);
	if (!gstrings || gstrings->len != features->total) {
		free(gstrings);
		return -1;
	}

	gfeatures = ni_ethtool_get_feature_values(ifname, features->total);
	if (!gfeatures || gfeatures->size != ni_ethtool_get_feature_blocks(features->total)) {
		free(gstrings);
		free(gfeatures);
		return -1;
	}

	for (i = 0; i < features->total; ++i) {
		struct ethtool_get_features_block *block;
		const char *name;
		unsigned int bit;

		name = (const char *)(gstrings->data + i * ETH_GSTRING_LEN);
		block = &gfeatures->features[i/32];
		bit = NI_BIT(i % 32U);

		/* don't even store unavailable + unchangeable features */
		if (!(block->available & bit) || (block->never_changed & bit))
			continue;

		if (!(feature = ni_ethtool_feature_new(name, i)))
			continue;

		feature->value = NI_ETHTOOL_FEATURE_OFF;
		if (block->active & bit)
			feature->value |= NI_ETHTOOL_FEATURE_ON;
		if ((block->requested & bit) ^ (block->active & bit))
			feature->value |= NI_ETHTOOL_FEATURE_REQUESTED;

		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: get ethtool feature[%u,%s] %s: %s%s",
				ifname, feature->index, name, feature->map.name,
				feature->value & NI_ETHTOOL_FEATURE_ON
					? "on" : "off",
				feature->value & NI_ETHTOOL_FEATURE_REQUESTED
					? " requested" : "");

		if (!ni_ethtool_features_add(features, feature)) {
			ni_warn("%s: unable to store feature %s: %m", ifname, name);
			ni_ethtool_feature_free(feature);
		}
	}

	free(gstrings);
	free(gfeatures);
	return 0;
}

static int
ni_ethtool_get_features_update(const char *ifname, ni_ethtool_features_t *features)
{
	struct ethtool_gfeatures *gfeatures;
	ni_ethtool_feature_t *feature;
	unsigned int i;

	ni_assert(features != NULL);

	if (!features || !features->total || !features->count)
		return -1;

	gfeatures = ni_ethtool_get_feature_values(ifname, features->total);
	if (!gfeatures || gfeatures->size != ni_ethtool_get_feature_blocks(features->total)) {
		free(gfeatures);
		return -1;
	}

	for (i = 0; i < features->count; ++i) {
		struct ethtool_get_features_block *block;
		unsigned int bit;

		feature = features->features[i];
		if (!feature || feature->index == -1U)
			continue;

		block = &gfeatures->features[feature->index/32];
		bit = NI_BIT(feature->index % 32U);

		feature->value = NI_ETHTOOL_FEATURE_OFF;
		if (block->active & bit)
			feature->value |= NI_ETHTOOL_FEATURE_ON;
		if ((block->requested & bit) ^ (block->active & bit))
			feature->value |= NI_ETHTOOL_FEATURE_REQUESTED;

		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: get ethtool feature[%u] %s: %s%s",
				ifname, feature->index, feature->map.name,
				feature->value & NI_ETHTOOL_FEATURE_ON
					? "on" : "off",
				feature->value & NI_ETHTOOL_FEATURE_REQUESTED
					? " requested" : "");
	}

	free(gfeatures);
	return 0;
}

static int
ni_ethtool_get_features(const char *ifname, ni_ethtool_t *ethtool)
{
	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_FEATURES))
		return -1;

	if (ethtool->features && ethtool->features->total)
		return ni_ethtool_get_features_update(ifname, ethtool->features);

	if (!(ethtool->features = ni_ethtool_features_new()))
		return -1;

	return ni_ethtool_get_features_init(ifname, ethtool->features);
}

static int
ni_ethtool_set_features(const char *ifname, ni_ethtool_t *ethtool,
			const ni_ethtool_features_t *cfg)
{
	return -1;
}


/*
 * pause (GPAUSEPARAM,SPAUSEPARAM)
 */
void
ni_ethtool_pause_free(ni_ethtool_pause_t *pause)
{
	free(pause);
}

ni_ethtool_pause_t *
ni_ethtool_pause_new(void)
{
	ni_ethtool_pause_t *pause;

	pause = calloc(1, sizeof(*pause));
	if (pause) {
		pause->autoneg = NI_TRISTATE_DEFAULT;
		pause->rx      = NI_TRISTATE_DEFAULT;
		pause->tx      = NI_TRISTATE_DEFAULT;
	}
	return pause;
}

static int
ni_ethtool_get_pause(const char *ifname, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPAUSEPARAM = {
		ETHTOOL_GPAUSEPARAM,	"get pause"
	};
	struct ethtool_pauseparam param;
	ni_ethtool_pause_t *pause;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE))
		return -1;

	ni_ethtool_pause_free(ethtool->pause);
	ethtool->pause = NULL;

	memset(&param, 0, sizeof(param));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GPAUSEPARAM, &param, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0)
		return ret;

	if (!(pause = ni_ethtool_pause_new()))
		return -1;

	ni_tristate_set(&pause->autoneg, param.autoneg);
	ni_tristate_set(&pause->rx,      param.rx_pause);
	ni_tristate_set(&pause->tx,      param.tx_pause);

	ethtool->pause = pause;
	return 0;
}

static int
ni_ethtool_set_pause(const char *ifname, ni_ethtool_t *ethtool, const ni_ethtool_pause_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPAUSEPARAM = {
		ETHTOOL_GPAUSEPARAM,	"get pause"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SPAUSEPARAM = {
		ETHTOOL_SPAUSEPARAM,	"set pause"
	};
	struct ethtool_pauseparam param;
	int ret;

	if (!cfg)
		return  1; /* nothing to set */
	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE))
		return -1; /* unsupported    */

	memset(&param, 0, sizeof(param));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GPAUSEPARAM, &param, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0)
		return ret;

	if (ni_tristate_is_set(cfg->autoneg))
		param.autoneg  = cfg->autoneg;
	if (ni_tristate_is_set(cfg->rx))
		param.rx_pause = cfg->rx;
	if (ni_tristate_is_set(cfg->tx))
		param.tx_pause = cfg->tx;

	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_SPAUSEPARAM, &param, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE,
				!(ret < 0 && errno == EOPNOTSUPP));
	return ret;
}

/*
 * main system refresh and setup functions
 */
ni_bool_t
ni_ethtool_refresh(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	ni_trace("%s(%s,%u)", __func__, dev ? dev->name : NULL,
					dev ? dev->link.ifindex : 0);

	if (!(ethtool = ni_ethtool_new()))
		return FALSE;

	if (dev->ethtool)
		ethtool->supported = dev->ethtool->supported;

	ni_ethtool_get_driver_info(dev->name, ethtool);
	ni_ethtool_get_link_settings(dev->name, ethtool);
	ni_ethtool_get_features(dev->name, ethtool);
	ni_ethtool_get_pause(dev->name, ethtool);

	ni_netdev_set_ethtool(dev, ethtool);
	return TRUE;
}

void
ni_system_ethtool_refresh(ni_netdev_t *dev)
{
	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
		return;

	if (dev->ethtool && !dev->ethtool->supported)
		return;

	ni_ethtool_refresh(dev);
}

int
ni_system_ethtool_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	ni_trace("%s(%s,%u)", __func__, dev ? dev->name : NULL, dev ? dev->link.ifindex : 0);

	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex || !cfg || !cfg->ethtool) {
		ni_trace("%s(%s,%u) not ready or invalid args",
				__func__, dev ? dev->name : NULL, dev ? dev->link.ifindex : 0);
		return -1;
	}

	if (!dev->ethtool && !ni_ethtool_refresh(dev)) {
		ni_trace("%s(%s,%u) no ethtool or refresh failed",
				__func__, dev ? dev->name : NULL, dev ? dev->link.ifindex : 0);
		return -1;
	}

	ni_ethtool_set_pause(dev->name, dev->ethtool, cfg->ethtool->pause);
	ni_ethtool_set_link_settings(dev->name, dev->ethtool, cfg->ethtool->link_settings);
	ni_ethtool_set_features(dev->name, dev->ethtool, cfg->ethtool->features);

	ni_ethtool_refresh(dev);
	return 0;
}

/*
 * main netdev ethtool struct get/set helpers
 */
void
ni_ethtool_free(ni_ethtool_t *ethtool)
{
	if (ethtool) {
		ni_ethtool_driver_info_free(ethtool->driver_info);
		ni_ethtool_link_settings_free(ethtool->link_settings);
		ni_ethtool_features_free(ethtool->features);
		ni_ethtool_pause_free(ethtool->pause);
		free(ethtool);
	}
}

unsigned int
ni_ethtool_supported_mask(void)
{
	static unsigned int supported = 0;
	unsigned int i;

	if (!supported) {
		for (i = 0; i < NI_ETHTOOL_SUPPORT_MAX; ++i)
			supported |= NI_BIT(i);
	}
	return supported;
}

ni_ethtool_t *
ni_ethtool_new(void)
{
	ni_ethtool_t *ethtool;

	ethtool = calloc(1, sizeof(*ethtool));
	if (ethtool) {
		ethtool->supported = ni_ethtool_supported_mask();
	}
	return ethtool;
}

ni_ethtool_t *
ni_netdev_get_ethtool(ni_netdev_t *dev)
{
	if (!dev->ethtool)
		dev->ethtool = ni_ethtool_new();
	return dev->ethtool;
}

void
ni_netdev_set_ethtool(ni_netdev_t *dev, ni_ethtool_t *ethtool)
{
	if (dev->ethtool)
		ni_ethtool_free(dev->ethtool);
	dev->ethtool = ethtool;
}

