/*
 *	DBus encapsulation of the ethtool service
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

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/ethtool.h>
#include <wicked/system.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"

/*
 * Extract ethtool properties from a dbug dict argument.
 * We're re-using device properties from ni_objectmodel_ethtool_service,
 * which are derived from changeDevice method configuration propeties.
 */
static ni_netdev_t *
ni_objectmodel_ethtool_request_arg(const ni_dbus_variant_t *argument)
{
        if (!ni_dbus_variant_is_dict(argument))
		return NULL;

	return ni_objectmodel_get_netif_argument(argument, NI_IFTYPE_UNKNOWN,
						&ni_objectmodel_ethtool_service);
}

/*
 * ethtool.changeDevice method
 */
static dbus_bool_t
ni_objectmodel_ethtool_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev, *cfg;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = ni_objectmodel_ethtool_request_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	if (ni_system_ethtool_setup(NULL, dev, cfg) < 0)  {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to apply ethtool settings");
		ni_netdev_put(cfg);
		return FALSE;
	}

	ni_netdev_put(cfg);
	return TRUE;
}


/*
 * retrieve an ethtool handle from dbus netif object
 */
static ni_ethtool_t *
ni_objectmodel_ethtool_handle(const ni_dbus_object_t *object,
		ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ethtool;

	return ni_netdev_get_ethtool(dev);
}

static const ni_ethtool_t *
ni_objectmodel_ethtool_read_handle(const ni_dbus_object_t *object,
		DBusError *error)
{
	return ni_objectmodel_ethtool_handle(object, FALSE, error);
}

static ni_ethtool_t *
ni_objectmodel_ethtool_write_handle(const ni_dbus_object_t *object,
		DBusError *error)
{
	return ni_objectmodel_ethtool_handle(object, TRUE, error);
}

/*
 * get/set ethtool.driver-info properties
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_driver_info(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_driver_info_t *info;
	ni_dbus_variant_t *supp;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(info = ethtool->driver_info))
		return FALSE;

	if (info->driver)
		ni_dbus_dict_add_string(result, "driver", info->driver);
	if (info->version)
		ni_dbus_dict_add_string(result, "version", info->version);
	if (info->bus_info)
		ni_dbus_dict_add_string(result, "bus-info", info->bus_info);
	if (info->fw_version)
		ni_dbus_dict_add_string(result, "firmware-version", info->fw_version);
	if (info->erom_version)
		ni_dbus_dict_add_string(result, "expansion-rom-version", info->erom_version);

	if (!info->supports.n_priv_flags && !info->supports.n_stats &&
	    !info->supports.testinfo_len && !info->supports.eedump_len &&
	    !info->supports.regdump_len)
		return TRUE;

	if ((supp = ni_dbus_dict_add(result, "supports"))) {
		ni_dbus_variant_init_dict(supp);
		if (info->supports.n_stats)
			ni_dbus_dict_add_bool(supp, "statistics", !!info->supports.n_stats);
		if (info->supports.n_priv_flags)
			ni_dbus_dict_add_bool(supp, "priv-flags", !!info->supports.n_priv_flags);
		if (info->supports.testinfo_len > 0)
			ni_dbus_dict_add_bool(supp, "test",          info->supports.testinfo_len > 0);
		if (info->supports.eedump_len > 0)
			ni_dbus_dict_add_bool(supp, "eeprom-access", info->supports.eedump_len > 0);
		if (info->supports.regdump_len > 0)
			ni_dbus_dict_add_bool(supp, "register-dump", info->supports.regdump_len > 0);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_driver_info(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_driver_info_t *info;
	const ni_dbus_variant_t *supp;
	ni_ethtool_t *ethtool;
	const char *str;
	dbus_bool_t bv;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_driver_info_free(ethtool->driver_info);
	if (!(ethtool->driver_info = ni_ethtool_driver_info_new()))
		return FALSE;

	info = ethtool->driver_info;
	if (ni_dbus_dict_get_string(argument, "driver", &str))
		ni_string_dup(&info->driver, str);
	if (ni_dbus_dict_get_string(argument, "version", &str))
		ni_string_dup(&info->version, str);
	if (ni_dbus_dict_get_string(argument, "bus-info", &str))
		ni_string_dup(&info->bus_info, str);
	if (ni_dbus_dict_get_string(argument, "firmware-version", &str))
		ni_string_dup(&info->fw_version, str);
	if (ni_dbus_dict_get_string(argument, "expansion-rom-version", &str))
		ni_string_dup(&info->erom_version, str);

	if ((supp = ni_dbus_dict_get(argument, "supports"))) {
		if (ni_dbus_dict_get_bool(supp, "statistics", &bv))
			info->supports.n_stats = bv ? 1 : 0;
		if (ni_dbus_dict_get_bool(supp, "priv-flags", &bv))
			info->supports.n_priv_flags = bv ? 1 : 0;
		if (ni_dbus_dict_get_bool(supp, "test", &bv))
			info->supports.testinfo_len = bv ? 1 : 0;
		if (ni_dbus_dict_get_bool(supp, "eeprom-access", &bv))
			info->supports.eedump_len = bv ? 1 : 0;
		if (ni_dbus_dict_get_bool(supp, "register-dump", &bv))
			info->supports.regdump_len= 1;
	}

	return TRUE;
}

/*
 * get/set ethtool.pause properties
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_pause(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_pause_t *pause;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(pause = ethtool->pause))
		return FALSE;

	if (ni_tristate_is_set(pause->autoneg))
		ni_dbus_dict_add_bool(result, "autoneg", pause->autoneg);
	if (ni_tristate_is_set(pause->rx))
		ni_dbus_dict_add_bool(result, "rx",      pause->rx);
	if (ni_tristate_is_set(pause->tx))
		ni_dbus_dict_add_bool(result, "tx",      pause->tx);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_pause(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_pause_t *pause;
	ni_ethtool_t *ethtool;
	dbus_bool_t bv;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_pause_free(ethtool->pause);
	if (!(ethtool->pause = ni_ethtool_pause_new()))
		return FALSE;

	pause = ethtool->pause;
	if (ni_dbus_dict_get_bool(argument, "autoneg", &bv))
		ni_tristate_set(&pause->autoneg, bv);
	if (ni_dbus_dict_get_bool(argument, "rx", &bv))
		ni_tristate_set(&pause->rx, bv);
	if (ni_dbus_dict_get_bool(argument, "tx", &bv))
		ni_tristate_set(&pause->tx, bv);

	return TRUE;
}


/*
 * ethtool service properties
 */
#define ETHTOOL_DICT_PROPERTY(type, dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			fstem_name, ni_objectmodel_##type, rw)
static const ni_dbus_property_t		ni_objectmodel_ethtool_properties[] = {
	ETHTOOL_DICT_PROPERTY(ethtool, driver-info, driver_info, RO),
	ETHTOOL_DICT_PROPERTY(ethtool, pause,       pause,       RO),
	{ NULL }
};

/*
 * ethtool service methods
 */
static const ni_dbus_method_t		ni_objectmodel_ethtool_methods[] = {
	{ "changeDevice",		"a{sv}",	ni_objectmodel_ethtool_setup },
	{ NULL }
};

/*
 * ethtool service definitions
 */
ni_dbus_service_t			ni_objectmodel_ethtool_service = {
	.name				= NI_OBJECTMODEL_ETHTOOL_INTERFACE,
	.methods			= ni_objectmodel_ethtool_methods,
	.properties			= ni_objectmodel_ethtool_properties,
};

