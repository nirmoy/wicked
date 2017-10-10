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
#include "dbus-common.h"
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
 * get/set ethtool link-setting properties
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_autoneg(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_link_settings_t *link;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;
	if (!(link = ethtool->link_settings) || !ni_tristate_is_set(link->autoneg))
		return FALSE;

	ni_dbus_variant_set_bool(result, ni_tristate_is_enabled(link->autoneg));
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_autoneg(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_link_settings_t *link;
	dbus_bool_t bv;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;
	if (!ethtool->link_settings && !(link = ni_ethtool_link_settings_new()))
		return FALSE;
	
	link = ethtool->link_settings;
	if (ni_dbus_variant_get_bool(argument, &bv))
		ni_tristate_set(&link->autoneg, bv);
	else
		link->autoneg = NI_TRISTATE_DISABLE;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_link_speed(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_link_settings_t *link;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;
	if (!(link = ethtool->link_settings) || !link->speed)
		return FALSE;

	ni_dbus_variant_set_uint32(result, link->speed);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_link_speed(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_link_settings_t *link;
	uint32_t u32;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;
	if (!ethtool->link_settings && !(link = ni_ethtool_link_settings_new()))
		return FALSE;
	
	link = ethtool->link_settings;
	if (ni_dbus_variant_get_uint32(argument, &u32))
		link->speed = u32;
	else
		link->speed = 0;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_port_type(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_link_settings_t *link;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;
	if (!(link = ethtool->link_settings) || link->port != 0xff)
		return FALSE;

	ni_dbus_variant_set_uint32(result, link->port);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_port_type(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_link_settings_t *link;
	uint32_t u32;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;
	if (!ethtool->link_settings && !(link = ni_ethtool_link_settings_new()))
		return FALSE;
	
	link = ethtool->link_settings;
	if (ni_dbus_variant_get_uint32(argument, &u32))
		link->port = u32;
	else
		link->port = 0xff;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_duplex(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_link_settings_t *link;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;
	if (!(link = ethtool->link_settings) || link->duplex != 0xff)
		return FALSE;

	ni_dbus_variant_set_uint32(result, link->duplex);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_duplex(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_link_settings_t *link;
	uint32_t u32;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;
	if (!ethtool->link_settings && !(link = ni_ethtool_link_settings_new()))
		return FALSE;
	
	link = ethtool->link_settings;
	if (ni_dbus_variant_get_uint32(argument, &u32))
		link->duplex = u32;
	else
		link->duplex = 0xff;
	return TRUE;
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
 * get/set ethtool.offload and other features
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_features(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	unsigned int i;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!ethtool->features || !ethtool->features->count)
		return FALSE;

	for (i = 0; i < ethtool->features->count; ++i) {
		const ni_ethtool_feature_t *feature;

		if (!(feature = ethtool->features->features[i]))
			continue;

		if (feature->value == NI_ETHTOOL_FEATURE_DEFAULT)
			continue;

		/* int32 for backward compatibility */
		ni_dbus_dict_add_int32(result, feature->map.name, feature->value);
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_features(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	const ni_dbus_dict_entry_t *entry;
	ni_ethtool_t *ethtool;
	unsigned int i;
	int32_t value;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_features_free(ethtool->features);
	if (!(ethtool->features = ni_ethtool_features_new()))
		return FALSE;

	for (i = 0; i < argument->array.len; ++i) {
		if (!(entry = &argument->dict_array_value[i]))
			continue;

		/* int32 for backward compatibility */
		ni_dbus_variant_get_int32(&entry->datum, &value);
		if (value < 0)
			continue;

		value &= NI_ETHTOOL_FEATURE_ON|NI_ETHTOOL_FEATURE_REQUESTED;
		ni_ethtool_features_set(ethtool->features, entry->key, value);
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

static dbus_bool_t
ni_objectmodel_ethtool_get_coalesce(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (ethtool->coalesce->supported == NI_TRISTATE_DISABLE)
		return FALSE;

	if (ethtool->coalesce->adaptive_rx != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "adaptive-rx", ethtool->coalesce->adaptive_rx);

	if (ethtool->coalesce->adaptive_tx != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "adaptive-tx", ethtool->coalesce->adaptive_tx);

	if (ethtool->coalesce->rx_usecs != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-usecs", ethtool->coalesce->rx_usecs);
	}
	if (ethtool->coalesce->rx_frames != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-frames", ethtool->coalesce->rx_frames);
	}
	if (ethtool->coalesce->rx_usecs_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-usecs-irq", ethtool->coalesce->rx_usecs_irq);
	}
	if (ethtool->coalesce->rx_frames_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-frames-irq", ethtool->coalesce->rx_frames_irq);
	}
	if (ethtool->coalesce->tx_usecs != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-usecs", ethtool->coalesce->tx_usecs);
	}
	if (ethtool->coalesce->tx_frames != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-frames", ethtool->coalesce->tx_frames);
	}
	if (ethtool->coalesce->tx_usecs_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-usecs-irq", ethtool->coalesce->tx_usecs_irq);
	}
	if (ethtool->coalesce->tx_frames_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-frames-irq", ethtool->coalesce->tx_frames_irq);
	}
	if (ethtool->coalesce->stats_block_usecs != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "stats-block-usecs", ethtool->coalesce->stats_block_usecs);
	}
	if (ethtool->coalesce->pkt_rate_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "pkt-rate-low", ethtool->coalesce->pkt_rate_low);
	}
	if (ethtool->coalesce->rx_usecs_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-usecs-low", ethtool->coalesce->rx_usecs_low);
	}
	if (ethtool->coalesce->rx_frames_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-frames-low", ethtool->coalesce->rx_frames_low);
	}
	if (ethtool->coalesce->tx_usecs_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-usecs-low", ethtool->coalesce->tx_usecs_low);
	}
	if (ethtool->coalesce->tx_frames_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-frames-low", ethtool->coalesce->tx_frames_low);
	}
	if (ethtool->coalesce->pkt_rate_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "pkt-rate-high", ethtool->coalesce->pkt_rate_high);
	}
	if (ethtool->coalesce->rx_usecs_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-usecs-high", ethtool->coalesce->rx_usecs_high);
	}
	if (ethtool->coalesce->rx_frames_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "rx-frames-high", ethtool->coalesce->rx_frames_high);
	}
	if (ethtool->coalesce->tx_usecs_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-usecs-high", ethtool->coalesce->tx_usecs_high);
	}
	if (ethtool->coalesce->tx_frames_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "tx-frames-high", ethtool->coalesce->tx_frames_high);
	}
	if (ethtool->coalesce->sample_interval != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_dbus_dict_add_uint32(result, "sample-interval", ethtool->coalesce->sample_interval);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_coalesce(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_dict_get_int32(argument, "adaptive-rx", &ethtool->coalesce->adaptive_rx))
		ethtool->coalesce->adaptive_rx = NI_TRISTATE_DEFAULT;

	if (!ni_dbus_dict_get_int32(argument, "adaptive-tx", &ethtool->coalesce->adaptive_tx))
		ethtool->coalesce->adaptive_tx = NI_TRISTATE_DEFAULT;

	if (!ni_dbus_dict_get_uint32(argument, "rx-usecs", &ethtool->coalesce->rx_usecs)) {
		ethtool->coalesce->rx_usecs = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-frames", &ethtool->coalesce->rx_frames)) {
		ethtool->coalesce->rx_frames = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-usecs-irq", &ethtool->coalesce->rx_usecs_irq)) {
		ethtool->coalesce->rx_usecs_irq = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-frames-irq", &ethtool->coalesce->rx_frames_irq)) {
		ethtool->coalesce->rx_frames_irq = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-usecs", &ethtool->coalesce->tx_usecs)) {
		ethtool->coalesce->tx_usecs = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-frames", &ethtool->coalesce->tx_frames)) {
		ethtool->coalesce->tx_frames = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-usecs-irq", &ethtool->coalesce->tx_usecs_irq)) {
		ethtool->coalesce->tx_usecs_irq = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-frames-irq", &ethtool->coalesce->tx_frames_irq)) {
		ethtool->coalesce->tx_frames_irq = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "stats-block-usecs", &ethtool->coalesce->stats_block_usecs)) {
		ethtool->coalesce->stats_block_usecs = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "pkt-rate-low", &ethtool->coalesce->pkt_rate_low)) {
		ethtool->coalesce->pkt_rate_low = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-usecs-low", &ethtool->coalesce->rx_usecs_low)) {
		ethtool->coalesce->rx_usecs_low = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-frames-low", &ethtool->coalesce->rx_frames_low)) {
		ethtool->coalesce->rx_frames_low = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-usecs-low", &ethtool->coalesce->tx_usecs_low)) {
		ethtool->coalesce->tx_usecs_low = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-frames-low", &ethtool->coalesce->tx_frames_low)) {
		ethtool->coalesce->tx_frames_low = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "pkt-rate-high", &ethtool->coalesce->pkt_rate_high)) {
		ethtool->coalesce->pkt_rate_high = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-usecs-high", &ethtool->coalesce->rx_usecs_high)) {
		ethtool->coalesce->rx_usecs_high = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "rx-frames-high", &ethtool->coalesce->rx_frames_high)) {
		ethtool->coalesce->rx_frames_high = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-usecs-high", &ethtool->coalesce->tx_usecs_high)) {
		ethtool->coalesce->tx_usecs_high = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "tx-frames-high", &ethtool->coalesce->tx_frames_high)) {
		ethtool->coalesce->tx_frames_high = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	if (!ni_dbus_dict_get_uint32(argument, "sample-interval", &ethtool->coalesce->sample_interval)) {
		ethtool->coalesce->sample_interval = NI_ETHTOOL_COALESCE_DEFAULT;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_eee(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (ethtool->eee->supported == NI_TRISTATE_DISABLE)
		return FALSE;

	if (ethtool->eee->status.enabled != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "enabled", ethtool->eee->status.enabled);
	if (ethtool->eee->status.active != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "active", ethtool->eee->status.active);

	if (ethtool->eee->speed.supported != NI_ETHTOOL_EEE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "supported", ethtool->eee->speed.supported);
	if (ethtool->eee->speed.advertised != NI_ETHTOOL_EEE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "advertise", ethtool->eee->speed.advertised);
	if (ethtool->eee->speed.lp_advertised != NI_ETHTOOL_EEE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "lp-advertised", ethtool->eee->speed.lp_advertised);

	if (ethtool->eee->tx_lpi.enabled != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "tx-lpi", ethtool->eee->tx_lpi.enabled);
	if (ethtool->eee->tx_lpi.timer != NI_ETHTOOL_EEE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-timer", ethtool->eee->tx_lpi.timer);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_eee(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_dict_get_int32(argument, "enabled", &ethtool->eee->status.enabled))
		ethtool->eee->status.enabled = NI_TRISTATE_DEFAULT;
	if (!ni_dbus_dict_get_int32(argument, "active",  &ethtool->eee->status.active))
		ethtool->eee->status.active = NI_TRISTATE_DEFAULT;

	if (!ni_dbus_dict_get_uint32(argument, "supported", &ethtool->eee->speed.supported))
		ethtool->eee->speed.supported = NI_ETHTOOL_EEE_DEFAULT;
	if (!ni_dbus_dict_get_uint32(argument, "advertise", &ethtool->eee->speed.advertised))
		ethtool->eee->speed.advertised = NI_ETHTOOL_EEE_DEFAULT;
	if (!ni_dbus_dict_get_uint32(argument, "lp-advertised", &ethtool->eee->speed.lp_advertised))
		ethtool->eee->speed.lp_advertised = NI_ETHTOOL_EEE_DEFAULT;

	if (!ni_dbus_dict_get_int32(argument, "tx-lpi", &ethtool->eee->tx_lpi.enabled))
		ethtool->eee->tx_lpi.enabled = NI_TRISTATE_DEFAULT;
	if (!ni_dbus_dict_get_uint32(argument, "tx-timer", &ethtool->eee->tx_lpi.timer))
		ethtool->eee->tx_lpi.timer = NI_ETHTOOL_EEE_DEFAULT;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_channels(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (ethtool->channels->supported == NI_TRISTATE_DISABLE)
		return FALSE;

	if (ethtool->channels->tx != NI_ETHTOOL_CHANNELS_DEFAULT) {
		ni_dbus_dict_add_int32(result, "tx", ethtool->channels->tx);
	}

	if (ethtool->channels->rx != NI_ETHTOOL_CHANNELS_DEFAULT) {
		ni_dbus_dict_add_int32(result, "rx", ethtool->channels->rx);
	}

	if (ethtool->channels->other != NI_ETHTOOL_CHANNELS_DEFAULT) {
		ni_dbus_dict_add_int32(result, "other", ethtool->channels->other);
	}

	if (ethtool->channels->combined != NI_ETHTOOL_CHANNELS_DEFAULT) {
		ni_dbus_dict_add_int32(result, "combined", ethtool->channels->combined);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_channels(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_dict_get_uint32(argument, "tx", &ethtool->channels->tx)) {
		ethtool->channels->tx = NI_ETHTOOL_CHANNELS_DEFAULT;
	}

	if (!ni_dbus_dict_get_uint32(argument, "rx", &ethtool->channels->rx)) {
		ethtool->channels->rx = NI_ETHTOOL_CHANNELS_DEFAULT;
	}

	if (!ni_dbus_dict_get_uint32(argument, "other", &ethtool->channels->other)) {
		ethtool->channels->other = NI_ETHTOOL_CHANNELS_DEFAULT;
	}

	if (!ni_dbus_dict_get_uint32(argument, "combined", &ethtool->channels->combined)) {
		ethtool->channels->combined = NI_ETHTOOL_CHANNELS_DEFAULT;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_ring(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (ethtool->ring->supported == NI_TRISTATE_DISABLE)
		return FALSE;

	if (ethtool->ring->tx != NI_ETHTOOL_RING_DEFAULT) {
		ni_dbus_dict_add_int32(result, "tx", ethtool->ring->tx);
	}

	if (ethtool->ring->rx != NI_ETHTOOL_RING_DEFAULT) {
		ni_dbus_dict_add_int32(result, "rx", ethtool->ring->rx);
	}

	if (ethtool->ring->rx_jumbo != NI_ETHTOOL_RING_DEFAULT) {
		ni_dbus_dict_add_int32(result, "rx-jumbo", ethtool->ring->rx_jumbo);
	}

	if (ethtool->ring->rx_mini != NI_ETHTOOL_RING_DEFAULT) {
		ni_dbus_dict_add_int32(result, "rx-mini", ethtool->ring->rx_mini);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_ring(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_dict_get_uint32(argument, "tx", &ethtool->ring->tx)) {
		ethtool->ring->tx = NI_ETHTOOL_RING_DEFAULT;
	}

	if (!ni_dbus_dict_get_uint32(argument, "rx", &ethtool->ring->rx)) {
		ethtool->ring->rx = NI_ETHTOOL_RING_DEFAULT;
	}

	if (!ni_dbus_dict_get_uint32(argument, "rx-jumbo", &ethtool->ring->rx_jumbo)) {
		ethtool->ring->rx_jumbo = NI_ETHTOOL_RING_DEFAULT;
	}

	if (!ni_dbus_dict_get_uint32(argument, "rx-mini", &ethtool->ring->rx_mini)) {
		ethtool->ring->rx_mini = NI_ETHTOOL_RING_DEFAULT;
	}

	return TRUE;
}

/*
 * ethtool service properties
 */
#define ETHTOOL_DICT_PROPERTY(type, dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			fstem_name, ni_objectmodel_##type, rw)
#define ETHTOOL_BOOL_PROPERTY(type, dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_BOOLEAN_AS_STRING, dbus_name, \
			fstem_name, ni_objectmodel_##type, rw)
#define ETHTOOL_UINT_PROPERTY(type, dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_UINT32_AS_STRING, dbus_name, \
			fstem_name, ni_objectmodel_##type, rw)

static const ni_dbus_property_t		ni_objectmodel_ethtool_properties[] = {
	/* read-only (show-xml) info    */
	ETHTOOL_DICT_PROPERTY(ethtool, driver-info, driver_info, RO),
	/* also setup config properties */
	ETHTOOL_BOOL_PROPERTY(ethtool, autoneg,     autoneg,     RO),
	ETHTOOL_UINT_PROPERTY(ethtool, link-speed,  link_speed,  RO),
	ETHTOOL_UINT_PROPERTY(ethtool, port-type,   port_type,   RO),
	ETHTOOL_UINT_PROPERTY(ethtool, duplex,      duplex,      RO),
	ETHTOOL_DICT_PROPERTY(ethtool, offload,     features,    RO),
	ETHTOOL_DICT_PROPERTY(ethtool, pause,       pause,       RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			eee, ni_objectmodel_ethtool, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			ring, ni_objectmodel_ethtool, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			coalesce, ni_objectmodel_ethtool, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			channels, ni_objectmodel_ethtool, RO),



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

