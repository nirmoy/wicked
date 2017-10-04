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
	NI_ETHTOOL_SKIP_DRIVER_INFO	= NI_BIT(0),
	NI_ETHTOOL_SKIP_PAUSE		= NI_BIT(1),
};

/*
 * ethtool cmd error logging utilities
 */
typedef struct ni_ethtool_cmd_info {
	int		cmd;
	const char *	name;
} ni_ethtool_cmd_info_t;

static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GDRVINFO	= { ETHTOOL_GDRVINFO,    "GDRVINFO" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPAUSEPARAM	= { ETHTOOL_GPAUSEPARAM, "GPAUSEPARAM" };
static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SPAUSEPARAM	= { ETHTOOL_SPAUSEPARAM, "SPAUSEPARAM" };

static int
ni_ethtool_call(const char *ifname, const ni_ethtool_cmd_info_t *ioc, void *evp)
{
	int ret, err;

	if ((ret = __ni_ethtool(ifname, ioc->cmd, evp)) < 0) {
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
	return calloc(1, sizeof(ni_ethtool_driver_info_t));
}

static int
ni_ethtool_get_driver_info(const char *ifname, ni_ethtool_t *ethtool)
{
	struct ethtool_drvinfo drv_info;
	ni_ethtool_driver_info_t *info;

	if (!ethtool || ethtool->unsupported & NI_ETHTOOL_SKIP_DRIVER_INFO)
		return -1;

	ni_ethtool_driver_info_free(ethtool->driver_info);
	ethtool->driver_info = NULL;

	memset(&drv_info, 0, sizeof(drv_info));
	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GDRVINFO, &drv_info) < 0) {
		if (errno != EOPNOTSUPP)
			ethtool->unsupported |= NI_ETHTOOL_SKIP_DRIVER_INFO;
		return -1;
	}

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

	if ((pause = calloc(1, sizeof(*pause)))) {
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

	if (!ethtool || ethtool->unsupported & NI_ETHTOOL_SKIP_PAUSE)
		return -1;

	ni_ethtool_pause_free(ethtool->pause);
	ethtool->pause = NULL;

	memset(&param, 0, sizeof(param));
	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GPAUSEPARAM, &param) < 0) {
		if (errno != EOPNOTSUPP)
			ethtool->unsupported |= NI_ETHTOOL_SKIP_PAUSE;
		return -1;
	}

	if (!(pause = ni_ethtool_pause_new()))
		return -1;

	ni_trace("%s: pauseparam.autoneg: %u", ifname, param.autoneg);
	ni_trace("%s: pauseparam.rx: %u",      ifname, param.rx_pause);
	ni_trace("%s: pauseparam.tx: %u",      ifname, param.tx_pause);

	ni_tristate_set(&pause->autoneg, param.autoneg);
	ni_tristate_set(&pause->rx,      param.rx_pause);
	ni_tristate_set(&pause->tx,      param.tx_pause);

	ethtool->pause = pause;
	return 0;
}

static int
ni_ethtool_set_pause(const char *ifname, const ni_ethtool_t *ethtool, const ni_ethtool_pause_t *cfg)
{
	struct ethtool_pauseparam param;
	ni_ethtool_pause_t *cur;

	if (!ethtool || ethtool->unsupported & NI_ETHTOOL_SKIP_PAUSE || !cfg)
		return -1;

	if (!(cur = ethtool->pause))
		return -1;

	memset(&param, 0, sizeof(param));
	param.autoneg  = ni_tristate_is_set(cfg->autoneg) ? cfg->autoneg : cur->autoneg;
	param.rx_pause = ni_tristate_is_set(cfg->rx)      ? cfg->rx      : cur->rx;
	param.tx_pause = ni_tristate_is_set(cfg->tx)      ? cfg->tx      : cur->tx;

	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_SPAUSEPARAM, &param) < 0)
		return -1;

	return 0;
}

/*
 * (ni_system_)ethtool refresh
 */
ni_bool_t
ni_ethtool_refresh(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;
	ni_bool_t apply = FALSE;

	ni_trace("%s(%s,%u)", __func__, dev ? dev->name : NULL, dev ? dev->link.ifindex : 0);

	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
		return apply;

	if (!(ethtool = ni_ethtool_new()))
		return apply;

	ethtool->unsupported = dev->ethtool ? dev->ethtool->unsupported : 0U;

	apply = ni_ethtool_get_driver_info(dev->name, ethtool) == 0 || apply;
	apply = ni_ethtool_get_pause(dev->name, ethtool) == 0 || apply;

	if (apply) {
		ni_netdev_set_ethtool(dev, ethtool);
	} else {
		ni_netdev_set_ethtool(dev, NULL);
		ni_ethtool_free(ethtool);
	}
	return apply;
}

int
ni_ethtool_setup(ni_netdev_t *dev, const ni_ethtool_t *cfg)
{
	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex || !cfg)
		return -1;

	if (!dev->ethtool || !ni_ethtool_refresh(dev))
		return -1;

	ni_ethtool_set_pause(dev->name, dev->ethtool, cfg->pause);

	return 0;
}

/*
 * main netdev ethtool struct get/set
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

