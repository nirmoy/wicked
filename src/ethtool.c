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

enum {
	NI_ETHTOOL_SUPP_DRIVER_INFO,
	NI_ETHTOOL_SUPP_LINK_LEGACY,
	NI_ETHTOOL_SUPP_LINK_SETTINGS,
	NI_ETHTOOL_SUPP_PAUSE,
};

static inline ni_bool_t
ni_ethtool_supported(const ni_ethtool_t *ethtool, unsigned int flag)
{
	return ethtool ? ethtool->supported & NI_BIT(flag) : FALSE;
}

static inline ni_bool_t
ni_ethtool_unsupported(const ni_ethtool_t *ethtool, unsigned int flag)
{
	return !ni_ethtool_supported(ethtool, flag);
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

static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSET		= { ETHTOOL_GSET,          "GSET" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SSET		= { ETHTOOL_SSET,          "SSET" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GDRVINFO	= { ETHTOOL_GDRVINFO,      "GDRVINFO" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPAUSEPARAM	= { ETHTOOL_GPAUSEPARAM,   "GPAUSEPARAM" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SPAUSEPARAM	= { ETHTOOL_SPAUSEPARAM,   "SPAUSEPARAM" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GLINKSETINGS	= { ETHTOOL_GLINKSETTINGS, "GLINKSETTINGS" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SLINKSETINGS	= { ETHTOOL_SLINKSETTINGS, "SLINKSETTINGS" };

static int
ni_ethtool_call(const char *ifname, const ni_ethtool_cmd_info_t *ioc, void *evp)
{
	int ret, err;

	ret = __ni_ethtool(ifname, ioc->cmd, evp);
	if (ret < 0) {
		err = errno;
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ethtool %s failed: %m", ifname, ioc->name);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool %s failed: %m", ifname, ioc->name);
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
	struct ethtool_drvinfo drv_info;
	ni_ethtool_driver_info_t *info;
	int ret;

	if (ni_ethtool_unsupported(ethtool, NI_ETHTOOL_SUPP_DRIVER_INFO))
		return -1;

	ni_ethtool_driver_info_free(ethtool->driver_info);
	ethtool->driver_info = NULL;

	memset(&drv_info, 0, sizeof(drv_info));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GDRVINFO, &drv_info);
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

ni_ethtool_link_settings_t *
ni_ethtool_link_settings_new(void)
{
	ni_ethtool_link_settings_t *settings;

	settings = calloc(1, sizeof(*settings));
	if (settings) {
		settings->autoneg = NI_TRISTATE_DEFAULT;
		settings->speed	  = 0; /* down link */
		settings->duplex  = DUPLEX_UNKNOWN;
		settings->port    = PORT_OTHER;
	}
	return settings;
}

void
ni_ethtool_link_settings_free(ni_ethtool_link_settings_t *settings)
{
	if (settings) {
		free(settings);
	}
}

/*
 * legacy link-settings (GSET,SSET)
 */
static int
ni_ethtool_get_legacy_settings(const char *ifname, ni_ethtool_t *ethtool)
{
	struct ethtool_cmd settings;
	ni_ethtool_link_settings_t *link;
	int ret;

	ni_trace("%s(%s) TODO", __func__, ifname);

	if (ni_ethtool_unsupported(ethtool, NI_ETHTOOL_SUPP_LINK_LEGACY))
		return -1;

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = NULL;

	memset(&settings, 0, sizeof(settings));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GSET, &settings);
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
	(void)ifname;
	(void)ethtool;
	(void)cfg;

	ni_trace("%s(%s) TODO", __func__, ifname);

	return 0;
}

/*
 * updated link-settings (GLINKSETTINGS,SLINKSETTINGS)
 */
static int
ni_ethtool_get_link_settings(const char *ifname, ni_ethtool_t *ethtool)
{
	struct ethtool_link_settings settings;
	ni_ethtool_link_settings_t *link;
	int ret;

	ni_trace("%s(%s)", __func__, ifname);

	if (ni_ethtool_unsupported(ethtool, NI_ETHTOOL_SUPP_LINK_SETTINGS))
		return ni_ethtool_get_legacy_settings(ifname, ethtool);

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = NULL;

	memset(&settings, 0, sizeof(settings));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GLINKSETINGS, &settings);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_LINK_SETTINGS,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0) {
		if (errno == EOPNOTSUPP)
			return ni_ethtool_get_legacy_settings(ifname, ethtool);
		return ret;
	}

	if (!(link = ni_ethtool_link_settings_new()))
		return -1;

	ni_trace("%s: get link-settins.speed: %u",	ifname, settings.speed);
	ni_trace("%s: get link-settins.duplex: %u",	ifname, settings.duplex);
	ni_trace("%s: get link-settins.port: %u",	ifname, settings.port);

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
	ni_trace("%s(%s)", __func__, ifname);

	if (ni_ethtool_unsupported(ethtool, NI_ETHTOOL_SUPP_LINK_SETTINGS))
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
	struct ethtool_pauseparam param;
	ni_ethtool_pause_t *pause;
	int ret;

	if (ni_ethtool_unsupported(ethtool, NI_ETHTOOL_SUPP_PAUSE))
		return -1;

	ni_ethtool_pause_free(ethtool->pause);
	ethtool->pause = NULL;

	memset(&param, 0, sizeof(param));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GPAUSEPARAM, &param);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE,
				!(ret < 0 && errno == EOPNOTSUPP));
	if (ret < 0)
		return ret;

	if (!(pause = ni_ethtool_pause_new()))
		return -1;

	ni_trace("%s: get pause param.autoneg: %u", ifname, param.autoneg);
	ni_trace("%s: get pause param.rx: %u",      ifname, param.rx_pause);
	ni_trace("%s: get pause param.tx: %u",      ifname, param.tx_pause);

	ni_tristate_set(&pause->autoneg, param.autoneg);
	ni_tristate_set(&pause->rx,      param.rx_pause);
	ni_tristate_set(&pause->tx,      param.tx_pause);

	ethtool->pause = pause;
	return 0;
}

static int
ni_ethtool_set_pause(const char *ifname, ni_ethtool_t *ethtool, const ni_ethtool_pause_t *cfg)
{
	struct ethtool_pauseparam param;
	ni_ethtool_pause_t *cur;

	ni_trace("%s(%s,ethtool=%p, cfg=%p)", __func__, ifname, ethtool, cfg);
	if (ni_ethtool_unsupported(ethtool, NI_ETHTOOL_SUPP_PAUSE))
		return -1;

	if (!cfg || !(cur = ethtool->pause))
		return -1;

	memset(&param, 0, sizeof(param));
	param.autoneg  = ni_tristate_is_set(cfg->autoneg) ? cfg->autoneg : cur->autoneg;
	param.rx_pause = ni_tristate_is_set(cfg->rx)      ? cfg->rx      : cur->rx;
	param.tx_pause = ni_tristate_is_set(cfg->tx)      ? cfg->tx      : cur->tx;

	ni_trace("%s: set pause (%d => %d) param.autoneg: %u",
			ifname, cur->autoneg, cfg->autoneg, param.autoneg);
	ni_trace("%s: set pause (%d => %d) param.rx: %u",
			ifname, cur->rx,      cfg->rx,      param.rx_pause);
	ni_trace("%s: set pause (%d => %d) param.tx: %u",
			ifname, cur->tx,      cfg->tx,      param.tx_pause);

	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_SPAUSEPARAM, &param) < 0) {
		if (errno == EOPNOTSUPP)
			ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_PAUSE, FALSE);
		return -1;
	}

	return 0;
}

/*
 * main system refresh and setup functions
 */
ni_bool_t
ni_ethtool_refresh(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;
	ni_bool_t apply = FALSE;

	ni_trace("%s(%s,%u)", __func__, dev ? dev->name : NULL, dev ? dev->link.ifindex : 0);

	if (!(ethtool = ni_ethtool_new()))
		return FALSE;

	ethtool->supported = dev->ethtool ? dev->ethtool->supported : -1U;

	apply = ni_ethtool_get_driver_info(dev->name, ethtool) == 0 || apply;
	apply = ni_ethtool_get_link_settings(dev->name, ethtool) == 0 || apply;
	apply = ni_ethtool_get_pause(dev->name, ethtool) == 0 || apply;

	if (apply) {
		ni_netdev_set_ethtool(dev, ethtool);
	} else {
		ni_netdev_set_ethtool(dev, NULL);
		ni_ethtool_free(ethtool);
	}
	return apply;
}

void
ni_system_ethtool_refresh(ni_netdev_t *dev)
{
	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
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

	ni_ethtool_refresh(dev);
	if (!dev->ethtool) {
		ni_trace("%s(%s,%u) no ethtool or refresh failed",
				__func__, dev ? dev->name : NULL, dev ? dev->link.ifindex : 0);
		return -1;
	}

	ni_ethtool_set_pause(dev->name, dev->ethtool, cfg->ethtool->pause);
	ni_ethtool_set_link_settings(dev->name, dev->ethtool, cfg->ethtool->link_settings);

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
		free(ethtool);
	}
}

ni_ethtool_t *
ni_ethtool_new(void)
{
	ni_ethtool_t *ethtool;

	ethtool = calloc(1, sizeof(*ethtool));
	if (ethtool) {
		ethtool->supported = -1U;
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

