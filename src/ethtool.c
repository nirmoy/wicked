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

