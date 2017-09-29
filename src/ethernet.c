/*
 * Routines for handling Ethernet devices.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <limits.h>
#include <errno.h>

#include <wicked/util.h>
#include <wicked/ethernet.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "kernel.h"

#define ALL_ADVERTISED_MODES			\
	(ADVERTISED_10baseT_Half |		\
	 ADVERTISED_10baseT_Full |		\
	 ADVERTISED_100baseT_Half |		\
	 ADVERTISED_100baseT_Full |		\
	 ADVERTISED_1000baseT_Half |		\
	 ADVERTISED_1000baseT_Full |		\
	 ADVERTISED_1000baseKX_Full|		\
	 ADVERTISED_2500baseX_Full |		\
	 ADVERTISED_10000baseT_Full |		\
	 ADVERTISED_10000baseKX4_Full |		\
	 ADVERTISED_10000baseKR_Full |		\
	 ADVERTISED_10000baseR_FEC |		\
	 ADVERTISED_20000baseMLD2_Full |	\
	 ADVERTISED_20000baseKR2_Full |		\
	 ADVERTISED_40000baseKR4_Full |		\
	 ADVERTISED_40000baseCR4_Full |		\
	 ADVERTISED_40000baseSR4_Full |		\
	 ADVERTISED_40000baseLR4_Full |		\
	 ADVERTISED_56000baseKR4_Full |		\
	 ADVERTISED_56000baseCR4_Full |		\
	 ADVERTISED_56000baseSR4_Full |		\
	 ADVERTISED_56000baseLR4_Full)

#define ALL_ADVERTISED_FLAGS			\
	(ADVERTISED_Autoneg |			\
	 ADVERTISED_TP |			\
	 ADVERTISED_AUI |			\
	 ADVERTISED_MII |			\
	 ADVERTISED_FIBRE |			\
	 ADVERTISED_BNC |			\
	 ADVERTISED_Pause |			\
	 ADVERTISED_Asym_Pause |		\
	 ADVERTISED_Backplane |			\
	 ALL_ADVERTISED_MODES)

static void	__ni_system_ethernet_get(const char *, ni_ethernet_t *);
static void	__ni_system_ethernet_set(const char *, ni_ethernet_t *);
static int	__ni_ethtool_get_gset(const char *, ni_ethernet_t *);
static void	ni_ethtool_offload_init(ni_ethtool_offload_t *);
static void	ni_ethtool_eee_init(ni_ethtool_eee_t *);
static void	ni_ethtool_ring_init(ni_ethtool_ring_t *);
static void	ni_ethtool_coalesce_init(ni_ethtool_coalesce_t *coalesce);
static void	ni_ethtool_channels_init(ni_ethtool_channels_t *);

/*
 * Allocate ethernet struct
 */
ni_ethernet_t *
ni_ethernet_new(void)
{
	ni_ethernet_t *ether;
	ether = xcalloc(1, sizeof(ni_ethernet_t));
	ni_link_address_init(&ether->permanent_address);
	ether->wol.support		= __NI_ETHERNET_WOL_DEFAULT;
	ether->wol.options		= __NI_ETHERNET_WOL_DEFAULT;
	ni_link_address_init(&ether->wol.sopass);
	ether->autoneg_enable		= NI_TRISTATE_DEFAULT;
	ni_ethtool_offload_init(&ether->offload);
	ni_ethtool_eee_init(&ether->eee);
	ni_ethtool_ring_init(&ether->ring);
	ni_ethtool_coalesce_init(&ether->coalesce);
	ni_ethtool_channels_init(&ether->channels);

	return ether;
}

void
ni_ethernet_free(ni_ethernet_t *ethernet)
{
	free(ethernet);
}

/*
 * Translate between port types and strings
 */
static ni_intmap_t	__ni_ethernet_port_types[] = {
	{ "tp",			NI_ETHERNET_PORT_TP	},
	{ "aui",		NI_ETHERNET_PORT_AUI	},
	{ "bnc",		NI_ETHERNET_PORT_BNC	},
	{ "mii",		NI_ETHERNET_PORT_MII	},
	{ "fibre",		NI_ETHERNET_PORT_FIBRE	},
	{ "da",			NI_ETHERNET_PORT_DA	},
	{ "none",		NI_ETHERNET_PORT_NONE	},
	{ "other",		NI_ETHERNET_PORT_OTHER	},

	{ NULL }
	};

ni_ether_port_t
ni_ethernet_name_to_port_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __ni_ethernet_port_types, &value) < 0)
		return NI_ETHERNET_PORT_DEFAULT;
	return value;
}

const char *
ni_ethernet_port_type_to_name(ni_ether_port_t port_type)
{
	return ni_format_uint_mapped(port_type, __ni_ethernet_port_types);
}

/*
 * Translate ethtool constants to our internal constants
 */
typedef struct __ni_ethtool_map {
	int		ethtool_value;
	int		wicked_value;
} __ni_ethtool_map_t;

static const __ni_ethtool_map_t	__ni_ethtool_speed_map[] = {
	{ SPEED_10,		10	},
	{ SPEED_100,		100	},
	{ SPEED_1000,		1000	},
	{ SPEED_2500,		2500	},
	{ SPEED_10000,		10000	},
	{ SPEED_20000,		20000	},
	{ SPEED_40000,		40000	},
	{ SPEED_56000,		56000	},
	{ 65535,		0	},
	{ -1,			-1	}
};

static const __ni_ethtool_map_t	__ni_ethtool_duplex_map[] = {
	{ DUPLEX_HALF,		NI_ETHERNET_DUPLEX_HALF },
	{ DUPLEX_FULL,		NI_ETHERNET_DUPLEX_FULL },
	{ 255,			NI_ETHERNET_DUPLEX_NONE },
	{ -1,			-1			}
};

static const __ni_ethtool_map_t	__ni_ethtool_port_map[] = {
	{ PORT_TP,		NI_ETHERNET_PORT_TP	},
	{ PORT_AUI,		NI_ETHERNET_PORT_AUI	},
	{ PORT_BNC,		NI_ETHERNET_PORT_BNC	},
	{ PORT_MII,		NI_ETHERNET_PORT_MII	},
	{ PORT_FIBRE,		NI_ETHERNET_PORT_FIBRE	},
	{ PORT_DA,		NI_ETHERNET_PORT_DA	},
	{ PORT_NONE,		NI_ETHERNET_PORT_NONE	},
	{ PORT_OTHER,		NI_ETHERNET_PORT_OTHER	},
	{ -1,			-1			}
};

static const __ni_ethtool_map_t	__ni_ethtool_wol_map[] = {
	{ WAKE_PHY,		(1<<NI_ETHERNET_WOL_PHY)	},
	{ WAKE_UCAST,		(1<<NI_ETHERNET_WOL_UCAST)	},
	{ WAKE_MCAST,		(1<<NI_ETHERNET_WOL_MCAST)	},
	{ WAKE_BCAST,		(1<<NI_ETHERNET_WOL_BCAST)	},
	{ WAKE_ARP,		(1<<NI_ETHERNET_WOL_ARP)	},
	{ WAKE_MAGIC,		(1<<NI_ETHERNET_WOL_MAGIC)	},
	{ WAKE_MAGICSECURE,	(1<<NI_ETHERNET_WOL_SECUREON)	},
	{ -1,			-1				}
};

static const ni_intmap_t	__ni_ethernet_wol_map[] = {
	{ "phy",		NI_ETHERNET_WOL_PHY	},
	{ "p",			NI_ETHERNET_WOL_PHY	},
	{ "unicast",		NI_ETHERNET_WOL_UCAST	},
	{ "u",			NI_ETHERNET_WOL_UCAST	},
	{ "multicast",		NI_ETHERNET_WOL_MCAST	},
	{ "m",			NI_ETHERNET_WOL_MCAST	},
	{ "broadcast",		NI_ETHERNET_WOL_BCAST	},
	{ "b",			NI_ETHERNET_WOL_BCAST	},
	{ "arp",		NI_ETHERNET_WOL_ARP	},
	{ "a",			NI_ETHERNET_WOL_ARP	},
	{ "magic",		NI_ETHERNET_WOL_MAGIC	},
	{ "g",			NI_ETHERNET_WOL_MAGIC	},
	{ "secure-on",		NI_ETHERNET_WOL_SECUREON},
	{ "s",			NI_ETHERNET_WOL_SECUREON},
	{ NULL,			-1U			}
};

const char *
ni_ethernet_wol_options_format(ni_stringbuf_t *buf, unsigned int options, const char *sep)
{
	if (buf) {
		ni_format_bitmap(buf, __ni_ethernet_wol_map, options, sep);
		return buf->string;
	}
	return NULL;
}

static int
__ni_ethtool_to_wicked(const __ni_ethtool_map_t *map, int value)
{
	while (map->wicked_value >= 0) {
		if (map->ethtool_value == value)
			return map->wicked_value;
		map++;
	}
	return -1;
}

static unsigned int
__ni_ethtool_to_wicked_bits(const __ni_ethtool_map_t *map, unsigned int mask)
{
	const __ni_ethtool_map_t *m;
	unsigned int ret = 0;

	for (m = map; m && m->wicked_value >= 0; m++) {
		if (m->ethtool_value & mask)
			ret |= m->wicked_value;
	}
	return ret;
}

static int
__ni_wicked_to_ethtool(const __ni_ethtool_map_t *map, int value)
{
	while (map->wicked_value >= 0) {
		if (map->wicked_value == value)
			return map->ethtool_value;
		map++;
	}
	return -1;
}

static unsigned int
__ni_wicked_to_ethtool_bits(const __ni_ethtool_map_t *map, unsigned int mask)
{
	const __ni_ethtool_map_t *m;
	unsigned int ret = 0;

	for (m = map; m && m->wicked_value >= 0; m++) {
		if (m->wicked_value & mask)
			ret |= m->ethtool_value;
	}
	return ret;
}

/*
 * Get/set ethtool values
 */
typedef struct __ni_ioctl_info {
	int		number;
	const char *	name;
} __ni_ioctl_info_t;

#ifndef ETHTOOL_GGRO
# define ETHTOOL_GGRO -1
# define ETHTOOL_SGRO -1
#endif

static __ni_ioctl_info_t __ethtool_gflags = { ETHTOOL_GFLAGS, "GFLAGS" };
static __ni_ioctl_info_t __ethtool_sflags = { ETHTOOL_SFLAGS, "SFLAGS" };
static __ni_ioctl_info_t __ethtool_gstrings = { ETHTOOL_GSTRINGS, "GSTRINGS" };
static __ni_ioctl_info_t __ethtool_gstats = { ETHTOOL_GSTATS, "GSTATS" };
static __ni_ioctl_info_t __ethtool_gwol = { ETHTOOL_GWOL, "GWOL" };
static __ni_ioctl_info_t __ethtool_swol = { ETHTOOL_SWOL, "SWOL" };

static int
__ni_ethtool_do(const char *ifname, __ni_ioctl_info_t *ioc, void *evp)
{
	if (__ni_ethtool(ifname, ioc->number, evp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_%s failed: %m", ifname, ioc->name);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ETHTOOL_%s failed: %m", ifname, ioc->name);
		return -1;
	}

	return 0;
}

static int
__ni_ethtool_get_value(const char *ifname, __ni_ioctl_info_t *ioc)
{
	struct ethtool_value eval;

	memset(&eval, 0, sizeof(eval));
	if (__ni_ethtool_do(ifname, ioc, &eval) < 0)
		return -1;

	return eval.data;
}

static int
__ni_ethtool_set_value(const char *ifname, __ni_ioctl_info_t *ioc, int value)
{
	struct ethtool_value eval;

	memset(&eval, 0, sizeof(eval));
	eval.data = value;
	return __ni_ethtool_do(ifname, ioc, &eval);
}

/*
 * Get list of strings
 */
static int
__ni_ethtool_get_strings(const char *ifname, int set_id, unsigned int num, struct ni_ethtool_counter *counters)
{
	typedef char eth_gstring[ETH_GSTRING_LEN];
	struct ethtool_gstrings *ap;
	eth_gstring *strings;
	unsigned int i;

	ap = xcalloc(1, sizeof(*ap) + num * ETH_GSTRING_LEN);
	ap->string_set = set_id;
	ap->len = num;

	if (__ni_ethtool_do(ifname, &__ethtool_gstrings, ap) < 0)
		return -1;

	strings = (eth_gstring *)(ap + 1);
	for (i = 0; i < ap->len; ++i)
		ni_string_dup(&counters[i].name, strings[i]);

	free(ap);
	return 0;
}

/*
 * Get statistics
 */
static int
__ni_ethtool_get_stats(const char *ifname, unsigned int num, struct ni_ethtool_counter *counters)
{
	struct ethtool_stats *sp;
	unsigned int i;
	uint64_t *stats;

	sp = xcalloc(1, sizeof(*sp) + num * sizeof(uint64_t));
	sp->n_stats = num;

	if (__ni_ethtool_do(ifname, &__ethtool_gstats, sp) < 0)
		return -1;

	stats = (uint64_t *)(sp + 1);
	for (i = 0; i < num; ++i)
		counters[i].value = stats[i];

	return 0;
}

/*
 * Get a value from ethtool, and convert to tristate.
 */
static int
__ni_ethtool_get_tristate(const char *ifname, __ni_ioctl_info_t *ioc)
{
	int value;

	if ((value = __ni_ethtool_get_value(ifname, ioc)) < 0)
		return NI_TRISTATE_DEFAULT;

	return value? NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
}

static int
__ni_ethtool_set_tristate(const char *ifname, __ni_ioctl_info_t *ioc, int value)
{
	int kern_value;

	if (value == NI_TRISTATE_DEFAULT)
		return 0;

	kern_value = (value == NI_TRISTATE_ENABLE);
	return __ni_ethtool_set_value(ifname, ioc, kern_value);
}

static int
__ni_ethtool_get_wol(const char *ifname, ni_ethernet_wol_t *wol)
{
	struct ethtool_wolinfo wolinfo;

	memset(&wolinfo, 0, sizeof(wolinfo));
	if (__ni_ethtool_do(ifname, &__ethtool_gwol, &wolinfo) < 0) {
		wol->support = wol->options = __NI_ETHERNET_WOL_DISABLE;
		wol->sopass.len = 0;
		return -1;
	}

	wol->support = __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map,
							wolinfo.supported);
	wol->options  = __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map,
							wolinfo.wolopts);

	if (wol->options & (1<<NI_ETHERNET_WOL_SECUREON)
	&&  NI_MAXHWADDRLEN > sizeof(wolinfo.sopass)) {
		wol->sopass.type = ARPHRD_ETHER;
		wol->sopass.len = sizeof(wolinfo.sopass);
		memcpy(&wol->sopass.data, wolinfo.sopass, sizeof(wolinfo.sopass));
	}

	if (ni_debug_guard(NI_LOG_DEBUG3, NI_TRACE_IFCONFIG)) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		if (wol->support != __NI_ETHERNET_WOL_DISABLE) {
			ni_format_bitmap(&buf, __ni_ethernet_wol_map,
						wol->support, "|");
		} else {
			ni_stringbuf_puts(&buf, "disabled");
		}
		ni_stringbuf_puts(&buf, " -- ");
		if (wol->options != __NI_ETHERNET_WOL_DISABLE) {
			ni_format_bitmap(&buf, __ni_ethernet_wol_map,
						wol->options, "|");
		} else {
			ni_stringbuf_puts(&buf, "disabled");
		}
		if (wol->sopass.len) {
			ni_stringbuf_printf(&buf, ", sopass: -set-");
		}
		ni_trace("%s: %s() %s", ifname, __func__, buf.string);
		ni_stringbuf_destroy(&buf);
	}

	return 0;
}

static int
__ni_ethtool_set_wol(const char *ifname, const ni_ethernet_wol_t *wol)
{
	struct ethtool_wolinfo wolinfo;

	if (wol->options == __NI_ETHERNET_WOL_DEFAULT)
		return 0;

	memset(&wolinfo, 0, sizeof(wolinfo));

	/* Try to grab existing options before setting. */
	if (__ni_ethtool_do(ifname, &__ethtool_gwol, &wolinfo) < 0)
		wolinfo.wolopts = wolinfo.supported = 0;

	/* dump the requested change */
	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		unsigned int old_options;

		old_options = __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map,
							wolinfo.wolopts);
		if (old_options != __NI_ETHERNET_WOL_DISABLE) {
			ni_format_bitmap(&buf, __ni_ethernet_wol_map,
						old_options, "|");
		} else {
			ni_stringbuf_puts(&buf, "disabled");
		}
		ni_stringbuf_puts(&buf, " -> ");
		if (wol->options != __NI_ETHERNET_WOL_DISABLE) {
			ni_format_bitmap(&buf, __ni_ethernet_wol_map,
						wol->options, "|");
		} else {
			ni_stringbuf_puts(&buf, "disabled");
		}
		if (wol->sopass.len && (wol->options & (1<<NI_ETHERNET_WOL_SECUREON)))
			ni_stringbuf_printf(&buf, ", sopass: -set-");

		ni_trace("%s: %s() %s", ifname, __func__, buf.string);
		ni_stringbuf_destroy(&buf);
	}

	/* apply new settings to wolinfo */
	wolinfo.wolopts = __ni_wicked_to_ethtool_bits(__ni_ethtool_wol_map,
							wol->options);
	if ((wol->options & (1<<NI_ETHERNET_WOL_SECUREON)) && wol->sopass.len) {
		if (wol->sopass.len != sizeof(wolinfo.sopass)) {
			ni_error("%s: invalid wake-on-lan sopass length", ifname);
			return -1;
		}
		memcpy(wolinfo.sopass, &wol->sopass.data, sizeof(wolinfo.sopass));
	}

	/* kindly reject a disable attempt when wol is unsupported */
	if (wol->support == __NI_ETHERNET_WOL_DISABLE &&
	    wol->options == __NI_ETHERNET_WOL_DISABLE) {
		ni_error("%s: cannot set wake-on-lan -- not supported", ifname);
		return -1;
	}

	/* reject unsupported flags, or we disable SWOL ioctl */
	if ((wolinfo.wolopts & wolinfo.supported) != wolinfo.wolopts) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		unsigned int bad = wolinfo.wolopts;

		bad &= ~(wolinfo.wolopts & wolinfo.supported);
		bad  = __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map, bad);
		ni_format_bitmap(&buf, __ni_ethernet_wol_map, bad, "|");
		ni_error("%s: cannot set unsupported wake-on-lan options: %s",
				ifname, buf.string);
		ni_stringbuf_destroy(&buf);
		return -1;
	}

	if (__ni_ethtool_do(ifname, &__ethtool_swol, &wolinfo) < 0) {
		ni_error("%s: cannot set new wake-on-lan settings: %m", ifname);
		return -1;
	}

	return 0;
}

static void
ni_ethtool_offload_init(ni_ethtool_offload_t *offload)
{
	if (offload) {
		offload->rx_csum	= NI_TRISTATE_DEFAULT;
		offload->tx_csum	= NI_TRISTATE_DEFAULT;
		offload->scatter_gather	= NI_TRISTATE_DEFAULT;
		offload->tso		= NI_TRISTATE_DEFAULT;
		offload->ufo		= NI_TRISTATE_DEFAULT;
		offload->gso		= NI_TRISTATE_DEFAULT;
		offload->gro		= NI_TRISTATE_DEFAULT;
		offload->lro		= NI_TRISTATE_DEFAULT;
		offload->rxvlan		= NI_TRISTATE_DEFAULT;
		offload->txvlan		= NI_TRISTATE_DEFAULT;
		offload->ntuple		= NI_TRISTATE_DEFAULT;
		offload->rxhash		= NI_TRISTATE_DEFAULT;
	}
}

static ni_bool_t
ni_ethtool_set_bool_single_param(const char *ifname, const char *eopt_name,
				 const char *name, __ni_ioctl_info_t *sflags, int value, int bitmask)
{
	if (__ni_ethtool_set_value(ifname, sflags, value) < 0) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: failed to set ethtool.%s.%s to %u: %m",
				ifname, eopt_name, name, value);
		return FALSE;
	}
	else {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: applied ethtool.%s.%s = %s", ifname, eopt_name, name,
				(value & bitmask) ? "set":"unset");
	}

	return TRUE;
}

static int
ni_ethtool_set_bool_param(const char *ifname, __ni_ioctl_info_t *sflags,
				const char *eopt_name, const char *name,
				int *curr, int want, int bitmask)
{
	if (want == NI_TRISTATE_DEFAULT)
		return 1;

	if (want == NI_TRISTATE_ENABLE) {
		if (*curr & bitmask)
			return 0;
		*curr |= bitmask;
	}
	else {
		if (!(*curr & bitmask))
			return 0;
		*curr &= ~bitmask;
	}

	if (ni_ethtool_set_bool_single_param(ifname, eopt_name, name, sflags, *curr, bitmask))
		return 0;

	return 1;
}

static int
__ni_ethtool_get_offload(const char *ifname, ni_ethtool_offload_t *offload)
{
	__ni_ioctl_info_t __ethtool_grxcsum = { ETHTOOL_GRXCSUM, "GRXCSUM" };
	__ni_ioctl_info_t __ethtool_gtxcsum = { ETHTOOL_GTXCSUM, "GTXCSUM" };
	__ni_ioctl_info_t __ethtool_gsg = { ETHTOOL_GSG, "GSG" };
	__ni_ioctl_info_t __ethtool_gtso = { ETHTOOL_GTSO, "GTSO" };
	__ni_ioctl_info_t __ethtool_gufo = { ETHTOOL_GUFO, "GUFO" };
	__ni_ioctl_info_t __ethtool_ggso = { ETHTOOL_GGSO, "GGSO" };
	__ni_ioctl_info_t __ethtool_ggro = { ETHTOOL_GGRO, "GGRO" };

	int value;

	if (ni_string_empty(ifname) || !offload)
		return -1;

	offload->rx_csum = __ni_ethtool_get_tristate(ifname, &__ethtool_grxcsum);
	offload->tx_csum = __ni_ethtool_get_tristate(ifname, &__ethtool_gtxcsum);
	offload->scatter_gather = __ni_ethtool_get_tristate(ifname, &__ethtool_gsg);
	offload->tso = __ni_ethtool_get_tristate(ifname, &__ethtool_gtso);
	offload->ufo = __ni_ethtool_get_tristate(ifname, &__ethtool_gufo);
	offload->gso = __ni_ethtool_get_tristate(ifname, &__ethtool_ggso);
	offload->gro = __ni_ethtool_get_tristate(ifname, &__ethtool_ggro);

	value = __ni_ethtool_get_value(ifname, &__ethtool_gflags);
	if (value >= 0) {
		offload->lro = (value & ETH_FLAG_LRO) ?
			NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
		offload->rxvlan = (value & ETH_FLAG_RXVLAN) ?
			NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
		offload->txvlan = (value & ETH_FLAG_TXVLAN) ?
			NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
		offload->ntuple = (value & ETH_FLAG_NTUPLE) ?
			NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
		offload->rxhash = (value & ETH_FLAG_RXHASH) ?
			NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
	}

	return 0;
}

static int
__ni_ethtool_set_offload(const char *ifname, ni_ethtool_offload_t *offload)
{
	int value = __ni_ethtool_get_value(ifname, &__ethtool_gflags);

	__ni_ioctl_info_t __ethtool_srxcsum = { ETHTOOL_SRXCSUM, "SRXCSUM" };
	__ni_ioctl_info_t __ethtool_stxcsum = { ETHTOOL_STXCSUM, "STXCSUM" };
	__ni_ioctl_info_t __ethtool_ssg = { ETHTOOL_SSG, "SSG" };
	__ni_ioctl_info_t __ethtool_stso = { ETHTOOL_STSO, "STSO" };
	__ni_ioctl_info_t __ethtool_sufo = { ETHTOOL_SUFO, "SUFO" };
	__ni_ioctl_info_t __ethtool_sgso = { ETHTOOL_SGSO, "SGSO" };
	__ni_ioctl_info_t __ethtool_sgro = { ETHTOOL_SGRO, "SGRO" };

	if (ni_string_empty(ifname) || !offload)
		return -1;

	__ni_ethtool_set_tristate(ifname, &__ethtool_srxcsum, offload->rx_csum);
	__ni_ethtool_set_tristate(ifname, &__ethtool_stxcsum, offload->tx_csum);
	__ni_ethtool_set_tristate(ifname, &__ethtool_ssg, offload->scatter_gather);
	__ni_ethtool_set_tristate(ifname, &__ethtool_stso, offload->tso);
	__ni_ethtool_set_tristate(ifname, &__ethtool_sufo, offload->ufo);
	__ni_ethtool_set_tristate(ifname, &__ethtool_sgso, offload->gso);
	__ni_ethtool_set_tristate(ifname, &__ethtool_sgro, offload->gro);

	if (value >= 0) {
		ni_ethtool_set_bool_param(ifname, &__ethtool_sflags,"offload", "lro",
			&value, offload->lro, ETH_FLAG_LRO);
		ni_ethtool_set_bool_param(ifname, &__ethtool_sflags,"offload", "rxvlan",
			&value, offload->rxvlan, ETH_FLAG_RXVLAN);
		ni_ethtool_set_bool_param(ifname, &__ethtool_sflags,"offload", "txvlan",
			&value, offload->txvlan, ETH_FLAG_TXVLAN);
		ni_ethtool_set_bool_param(ifname, &__ethtool_sflags,"offload", "ntuple",
			&value, offload->ntuple, ETH_FLAG_NTUPLE);
		ni_ethtool_set_bool_param(ifname, &__ethtool_sflags,"offload", "rxhash",
			&value, offload->rxhash, ETH_FLAG_RXHASH);
	}

	return 0;
}

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
	/*
	 * mapping id constant to name normalizes to first name of the constant
	 * we normalize to the kernel name as needed to handle unknown features
	 */
	{ "tx-scatter-gather",			NI_ETHTOOL_FEATURE_SG			},
/*l*/	{ "scatter-gather",			NI_ETHTOOL_FEATURE_SG			},
/*s*/	{ "sg",					NI_ETHTOOL_FEATURE_SG			},
	{ "tx-checksum-ipv4",			NI_ETHTOOL_FEATURE_IP_CSUM		},
	{ "tx-checksum-ip-generic",		NI_ETHTOOL_FEATURE_HW_CSUM		},
/*l*/	{ "tx-checksumming",			NI_ETHTOOL_FEATURE_HW_CSUM		},
/*s*/	{ "tx",					NI_ETHTOOL_FEATURE_HW_CSUM		},
	{ "tx-checksum-ipv6",			NI_ETHTOOL_FEATURE_IPV6_CSUM		},
	{ "highdma",				NI_ETHTOOL_FEATURE_HIGHDMA		},
	{ "tx-scatter-gather-fraglist",		NI_ETHTOOL_FEATURE_FRAGLIST		},
	{ "tx-vlan-hw-insert",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX	},
/*l*/	{ "tx-vlan-offload",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX	},
/*s*/	{ "txvlan",				NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_TX	},
	{ "rx-vlan-hw-parse",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX	},
/*l*/	{ "rx-vlan-offload",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX	},
/*s*/	{ "rxvlan",				NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_RX	},
	{ "rx-vlan-filter",			NI_ETHTOOL_FEATURE_HW_VLAN_CTAG_FILTER	},
	{ "tx-vlan-stag-hw-insert",		NI_ETHTOOL_FEATURE_HW_VLAN_STAG_TX	},
	{ "rx-vlan-stag-hw-parse",		NI_ETHTOOL_FEATURE_HW_VLAN_STAG_RX	},
	{ "rx-vlan-stag-filter",		NI_ETHTOOL_FEATURE_HW_VLAN_STAG_FILTER	},
	{ "vlan-challenged",			NI_ETHTOOL_FEATURE_VLAN_CHALLENGED	},
	{ "tx-generic-segmentation",		NI_ETHTOOL_FEATURE_GSO			},
/*l*/	{ "generic-segmentation-offload",	NI_ETHTOOL_FEATURE_GSO			},
/*s*/	{ "gso",				NI_ETHTOOL_FEATURE_GSO			},
	{ "tx-lockless",			NI_ETHTOOL_FEATURE_LLTX			},
	{ "netns-local",			NI_ETHTOOL_FEATURE_NETNS_LOCAL		},
	{ "rx-gro",				NI_ETHTOOL_FEATURE_GRO			},
/*l*/	{ "generic-receive-offload",		NI_ETHTOOL_FEATURE_GRO			},
/*s*/	{ "gro",				NI_ETHTOOL_FEATURE_GRO			},
	{ "rx-lro",				NI_ETHTOOL_FEATURE_LRO			},
/*l*/	{ "large-receive-offload",		NI_ETHTOOL_FEATURE_LRO			},
/*s*/	{ "lro",				NI_ETHTOOL_FEATURE_LRO			},
	{ "tx-tcp-segmentation",		NI_ETHTOOL_FEATURE_TSO			},
/*l*/	{ "tcp-segmentation-offload",		NI_ETHTOOL_FEATURE_TSO			},
/*s*/	{ "tso",				NI_ETHTOOL_FEATURE_TSO			},
	{ "tx-udp-fragmentation",		NI_ETHTOOL_FEATURE_UFO			},
/*l*/	{ "udp-fragmentation-offload",		NI_ETHTOOL_FEATURE_UFO			},
/*s*/	{ "ufo",				NI_ETHTOOL_FEATURE_UFO			},
#if 0	/* to have some unknown features */
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
#endif
	{ "rx-ntuple-filter",			NI_ETHTOOL_FEATURE_NTUPLE		},
/*l*/	{ "ntuple-filters",			NI_ETHTOOL_FEATURE_NTUPLE		},
/*s*/	{ "ntuple",				NI_ETHTOOL_FEATURE_NTUPLE		},
	{ "rx-hashing",				NI_ETHTOOL_FEATURE_RXHASH		},
/*l*/	{ "receive-hashing",			NI_ETHTOOL_FEATURE_RXHASH		},
/*s*/	{ "rxhash",				NI_ETHTOOL_FEATURE_RXHASH		},
	{ "rx-checksum",			NI_ETHTOOL_FEATURE_RXCSUM		},
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

const char *
ni_ethtool_feature_id_to_name(unsigned int id)
{
	return ni_format_uint_mapped(id, ni_ethtool_feature_name_map);
}
ni_bool_t
ni_ethtool_feature_name_to_id(const char *name, unsigned int *id)
{
	return ni_parse_uint_mapped(name, ni_ethtool_feature_name_map, id) == 0;
}
ni_bool_t
ni_ethtool_feature_map_name(const char *name, ni_intmap_t *ret)
{
	const ni_intmap_t *map = ni_ethtool_feature_name_map;

	if (!name || !ret || !map)
		return FALSE;

	for ( ; map->name; ++map) {
		if (strcasecmp(map->name, name))
			continue;

		ret->name = map->name;
		ret->value = map->value;
		return TRUE;
	}
	return FALSE;
}

typedef struct ni_ethtool_feature {
	ni_intmap_t		id;
	unsigned int		index;
	unsigned int		value;
} ni_ethtool_feature_t;

typedef struct ni_ethtool_feature_array {
	unsigned int		count;
	ni_ethtool_feature_t **	data;
} ni_ethtool_feature_array_t;

#define	NI_ETHTOOL_FEATURE_ARRAY_INIT		{ .count = 0, .data = NULL }
#define NI_ETHTOOL_FEATURE_ARRAY_CHUNK		32

void
ni_ethtool_feature_free(ni_ethtool_feature_t *feature)
{
	if (feature) {
		if (feature->id.value == NI_ETHTOOL_FEATURE_UNKNOWN)
			free((char *)feature->id.name);
		feature->id.name = NULL;
		free(feature);
	}
}

ni_ethtool_feature_t *
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
	if (ni_ethtool_feature_map_name(name, &feature->id))
		return feature;

	/* or deep copy unknown feature name */
	feature->id.value = NI_ETHTOOL_FEATURE_UNKNOWN;
	if (ni_string_dup(&copy, name) && (feature->id.name = copy))
		return feature;

	ni_ethtool_feature_free(feature);
	return NULL;
}

void
ni_ethtool_feature_array_init(ni_ethtool_feature_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_ethtool_feature_array_destroy(ni_ethtool_feature_array_t *array)
{
	if (array) {
		while (array->count--)
			ni_ethtool_feature_free(array->data[array->count]);
		free(array->data);
		ni_ethtool_feature_array_init(array);
	}
}

static ni_bool_t
ni_ethtool_feature_array_realloc(ni_ethtool_feature_array_t *array, unsigned int newsize)
{
	ni_ethtool_feature_t **newdata;
	unsigned int i;

	if (!array || (UINT_MAX - NI_ETHTOOL_FEATURE_ARRAY_CHUNK) <= newsize)
		return FALSE;

	newsize = (newsize + NI_ETHTOOL_FEATURE_ARRAY_CHUNK);
	newdata = realloc(array->data, newsize * sizeof(*newdata));
	if (!newdata)
		return FALSE;

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
	return TRUE;
}

ni_bool_t
ni_ethtool_feature_array_append(ni_ethtool_feature_array_t *array, ni_ethtool_feature_t *feature)
{
	if (!array || !feature)
		return FALSE;

	if ((array->count % NI_ETHTOOL_FEATURE_ARRAY_CHUNK) == 0 &&
	    !ni_ethtool_feature_array_realloc(array, array->count))
		return FALSE;

	array->data[array->count++] = feature;
	return TRUE;
}

uint32_t
ni_ethtool_get_feature_count(const char *ifname)
{
	struct {
		struct ethtool_sset_info hdr;
		uint32_t buf[1];
	} sset_info;

	sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
	sset_info.hdr.reserved = 0;
	sset_info.hdr.sset_mask = 1ULL << ETH_SS_FEATURES;
	if (__ni_ethtool(ifname, sset_info.hdr.cmd, &sset_info) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_GSSET_INFO failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
					"%s: ETHTOOL_GSSET_INFO failed: %m", ifname);
	} else
	if (sset_info.hdr.sset_mask == (1ULL << ETH_SS_FEATURES)) {
		return sset_info.hdr.data[0];
	}

	return 0;
}

static struct ethtool_gstrings *
ni_ethtool_get_feature_strings(const char *ifname)
{
	struct ethtool_gstrings *gstrings;
	unsigned int count, i;

	count = ni_ethtool_get_feature_count(ifname);
	if (!count)
		return NULL;

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
			"%s: ethtool.features: %u", ifname, count);

	gstrings = calloc(1, sizeof(*gstrings) + count * ETH_GSTRING_LEN);
	if (!gstrings) {
		ni_warn("%s: unable to allocate %u ethtool feature gstrings", ifname, count);
		return NULL;
	}

	gstrings->cmd = ETHTOOL_GSTRINGS;
	gstrings->string_set = ETH_SS_FEATURES;
	gstrings->len = count;
	if (__ni_ethtool(ifname, gstrings->cmd, gstrings) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_GSTRINGS failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
					"%s: ETHTOOL_GSTRINGS failed: %m", ifname);

		free(gstrings);
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
	struct ethtool_gfeatures *gfeatures;
	unsigned int blocks;

	blocks = ni_ethtool_get_feature_blocks(count);
	gfeatures = calloc(1, sizeof(*gfeatures) + blocks * sizeof(gfeatures->features[0]));
	if (!gfeatures)
		return NULL;

	gfeatures->cmd  = ETHTOOL_GFEATURES;
	gfeatures->size = blocks;
	if (__ni_ethtool(ifname, gfeatures->cmd, gfeatures) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_GFEATURES failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
					"%s: ETHTOOL_GFEATURES failed: %m", ifname);
		free(gfeatures);
		return NULL;
	}
	return gfeatures;
}

static int
ni_ethtool_get_features(const char *ifname/*, ni_ethtool_features_t *...*/)
{
	ni_ethtool_feature_array_t features = NI_ETHTOOL_FEATURE_ARRAY_INIT;
	ni_ethtool_feature_t *feature;
	struct ethtool_gstrings *gstrings;
	struct ethtool_gfeatures *gfeatures;
	unsigned int i;
	char * bin(unsigned int n) {
		unsigned int i, j = 0;
		static char bins[33] = {0};

		memset(bins, 0, sizeof(bins));
		for (i = 1 << 31; i > 0; i = i / 2) {
			(n & i) ? (bins[j] = '1') : (bins[j] = '0');
			j++;
		}
		return bins;
	}


	gstrings = ni_ethtool_get_feature_strings(ifname);
	if (!gstrings)
		return -1;

	gfeatures = ni_ethtool_get_feature_values(ifname, gstrings->len);
	if (!gfeatures) {
		free(gstrings);
		return -1;
	}
	if (gfeatures->size != ni_ethtool_get_feature_blocks(gstrings->len)) {
		free(gstrings);
		free(gfeatures);
		return -1;
	}
	for (i = 0; i < ni_ethtool_get_feature_blocks(gstrings->len); ++i) {
		struct ethtool_get_features_block *block;
		block = &gfeatures->features[i];
		ni_trace("%s: gfeature [%u].available: %s", ifname, i, bin(block->available));
		ni_trace("%s: gfeature [%u].requested: %s", ifname, i, bin(block->requested));
		ni_trace("%s: gfeature [%u].active:    %s", ifname, i, bin(block->active));
		ni_trace("%s: gfeature [%u].unchanged: %s", ifname, i, bin(block->never_changed));
	}

	for (i = 0; i < gstrings->len; ++i) {
		struct ethtool_get_features_block *block;
		const char *name;

		name = (const char *)(gstrings->data + i * ETH_GSTRING_LEN);
		block = &gfeatures->features[i/32];

		if (!(feature = ni_ethtool_feature_new(name, i)))
			continue;

		if (!ni_ethtool_feature_array_append(&features, feature))
			ni_ethtool_feature_free(feature);
		else
			ni_trace("%s: feature[%u]: %s%s, index: %u, id: %u",
				ifname, i, feature->id.name,
				feature->id.value == NI_ETHTOOL_FEATURE_UNKNOWN ?
				" [unknown]" : "",
				feature->index, feature->id.value);
	}

	ni_ethtool_feature_array_destroy(&features);
	return 0;
}

static int
__ni_ethtool_get_permanent_address(const char *ifname, ni_hwaddr_t *perm_addr)
{
	struct {
		struct ethtool_perm_addr h;
		unsigned char data[NI_MAXHWADDRLEN];
	} parm;

	if (ni_string_empty(ifname) || !perm_addr)
		return -1;

	memset(&parm, 0, sizeof(parm));
	parm.h.size = sizeof(parm.data);
	if (__ni_ethtool(ifname, ETHTOOL_GPERMADDR, &parm) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_GPERMADDR failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ETHTOOL_GPERMADDR failed: %m", ifname);
		return -1;
	}
	else if (ni_link_address_length(perm_addr->type) == parm.h.size) {
		ni_link_address_set(perm_addr, perm_addr->type, parm.data, parm.h.size);
	}

	return 0;
}

/*
 * Handle ethtool stats
 */
ni_ethtool_stats_t *
__ni_ethtool_stats_init(const char *ifname, const struct ethtool_drvinfo *drv_info)
{
	ni_ethtool_stats_t *stats;

	stats = xcalloc(1, sizeof(*stats));
	stats->count = drv_info->n_stats;
	stats->data = xcalloc(stats->count, sizeof(struct ni_ethtool_counter));

	if (__ni_ethtool_get_strings(ifname, ETH_SS_STATS, stats->count, stats->data) < 0) {
		__ni_ethtool_stats_free(stats);
		return NULL;
	}

	return stats;
}

int
__ni_ethtool_stats_refresh(const char *ifname, ni_ethtool_stats_t *stats)
{
	return __ni_ethtool_get_stats(ifname, stats->count, stats->data);
}

void
__ni_ethtool_stats_free(ni_ethtool_stats_t *stats)
{
	unsigned int i;

	for (i = 0; i < stats->count; ++i)
		ni_string_free(&stats->data[i].name);
	free(stats->data);
	free(stats);
}

/*
 * Get ethtool settings from the kernel
 */
void
__ni_system_ethernet_refresh(ni_netdev_t *dev)
{
	ni_ethernet_t *ether;

	ether = ni_ethernet_new();
	ether->permanent_address.type = dev->link.hwaddr.type;

	/* "unset" defaults until it is ready (using it's final name) */
	if (ni_netdev_device_is_ready(dev))
		__ni_system_ethernet_get(dev->name, ether);

	ni_netdev_set_ethernet(dev, ether);
}

ni_bool_t
ni_ethtool_validate_uint_param(unsigned int *curr, unsigned int wanted,
		unsigned int max, const char *type, const char *rparam, const char *ifname)
{
	if (wanted == NI_ETHTOOL_RING_DEFAULT)
		return FALSE;

	if (!curr || *curr == wanted)
		return FALSE;

	if (wanted > max) {
		ni_warn("%s: ethtool.%s.%s option crossed max(%u) limit",
				ifname, type, rparam, max);
		return FALSE;
	}

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
			"%s: ethtool.%s.%s option changed from %u to %u\n",
			ifname, type, rparam, *curr, wanted);
	*curr = wanted;
	return TRUE;
}

static void
ni_ethtool_coalesce_init(ni_ethtool_coalesce_t *coalesce)
{
	if (coalesce) {
		coalesce->supported = NI_TRISTATE_DEFAULT;

		coalesce->adaptive_tx = NI_TRISTATE_DEFAULT;
		coalesce->adaptive_rx = NI_TRISTATE_DEFAULT;

		coalesce->pkt_rate_low = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->pkt_rate_high = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->sample_interval = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->stats_block_usecs = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->rx_usecs = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_usecs_irq = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_usecs_low = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_usecs_high = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->rx_frames = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_frames_irq = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_frames_high = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_frames_low = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->tx_usecs = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_usecs_irq = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_usecs_low = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_usecs_high = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->tx_frames = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_frames_irq = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_frames_low = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_frames_high = NI_ETHTOOL_COALESCE_DEFAULT;
	}
}

static int
ni_ethtool_get_coalesce(const char *ifname, ni_ethtool_coalesce_t *coalesce)
{
	struct ethtool_coalesce tmp;

	if (coalesce->supported == NI_TRISTATE_DISABLE)
		return -1;

	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GCOALESCE, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.coalesce options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.coalesce options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			coalesce->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	ni_tristate_set(&coalesce->adaptive_tx, tmp.use_adaptive_tx_coalesce);
	ni_tristate_set(&coalesce->adaptive_rx, tmp.use_adaptive_rx_coalesce);

	coalesce->pkt_rate_low		= tmp.pkt_rate_low;
	coalesce->pkt_rate_high		= tmp.pkt_rate_high;

	coalesce->sample_interval	= tmp.rate_sample_interval;
	coalesce->stats_block_usecs	= tmp.stats_block_coalesce_usecs;

	coalesce->rx_usecs		= tmp.rx_coalesce_usecs;
	coalesce->rx_usecs_irq		= tmp.rx_coalesce_usecs_irq;
	coalesce->rx_usecs_low		= tmp.rx_coalesce_usecs_low;
	coalesce->rx_usecs_high		= tmp.rx_coalesce_usecs_high;

	coalesce->rx_frames		= tmp.rx_max_coalesced_frames;
	coalesce->rx_frames_irq		= tmp.rx_max_coalesced_frames_irq;
	coalesce->rx_frames_low		= tmp.rx_max_coalesced_frames_low;
	coalesce->rx_frames_high	= tmp.rx_max_coalesced_frames_high;

	coalesce->tx_usecs		= tmp.tx_coalesce_usecs;
	coalesce->tx_usecs_irq		= tmp.tx_coalesce_usecs_irq;
	coalesce->tx_usecs_low		= tmp.tx_coalesce_usecs_low;
	coalesce->tx_usecs_high		= tmp.tx_coalesce_usecs_high;

	coalesce->tx_frames		= tmp.tx_max_coalesced_frames;
	coalesce->tx_frames_irq		= tmp.tx_max_coalesced_frames_irq;
	coalesce->tx_frames_low		= tmp.tx_max_coalesced_frames_low;
	coalesce->tx_frames_high	= tmp.tx_max_coalesced_frames_high;

	return 0;
}

static ni_bool_t
ni_ethtool_set_uint_single_param(const char *ifname, void *eopt,
				int eopt_code, const char *eopt_name,
				const char *name, unsigned int value)
{
	if (__ni_ethtool(ifname, eopt_code, eopt) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: failed to set ethtool.%s.%s to %u: %m",
					ifname, eopt_name, name, value);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
					"%s: failed to set ethtool.%s.%s to %u: %m",
					ifname, eopt_name, name, value);
		return FALSE;
	}
	else {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: applied ethtool.%s.%s = %u", ifname, eopt_name, name, value);
	}

	return TRUE;
}

static int
ni_ethtool_set_uint_param(const char *ifname, void *eopt,
				int eopt_code, const char *eopt_name,
				const char *name,   unsigned int max,
				unsigned int *curr, unsigned int want)
{
	unsigned int save = *curr;

	if (!ni_ethtool_validate_uint_param(curr, want, max, eopt_name, name, ifname))
		return 1;

	if (ni_ethtool_set_uint_single_param(ifname, eopt, eopt_code, eopt_name, name, want))
		return 0;

	*curr = save;
	return 1;
}

static int
ni_ethtool_set_coalesce(const char *ifname, ni_ethtool_coalesce_t *coalesce)
{
	struct ethtool_coalesce tmp;

	if (coalesce->supported == NI_TRISTATE_DISABLE)
		return -1;

	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GCOALESCE, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.coalesce options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.coalesce options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			coalesce->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "adaptive_tx", NI_TRISTATE_ENABLE,
			&tmp.use_adaptive_tx_coalesce, coalesce->adaptive_tx);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "adaptive_rx", NI_TRISTATE_ENABLE,
			&tmp.use_adaptive_rx_coalesce, coalesce->adaptive_rx);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "pkt_rate_low", NI_ETHTOOL_COALESCE_DEFAULT,
			&tmp.pkt_rate_low, coalesce->pkt_rate_low);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "pkt_rate_high", NI_ETHTOOL_COALESCE_DEFAULT,
			&tmp.pkt_rate_high, coalesce->pkt_rate_high);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "sample_interval", NI_ETHTOOL_COALESCE_DEFAULT,
			&tmp.rate_sample_interval, coalesce->sample_interval);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "stats_block_usecs", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.stats_block_coalesce_usecs, coalesce->stats_block_usecs);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_usecs", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_coalesce_usecs, coalesce->rx_usecs);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_usecs_irq", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_coalesce_usecs_irq, coalesce->rx_usecs_irq);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_usecs_low", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_coalesce_usecs_low, coalesce->rx_usecs_low);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_usecs_high", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_coalesce_usecs_high, coalesce->rx_usecs_high);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_frames", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.use_adaptive_rx_coalesce, coalesce->rx_frames);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_frames_irq", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_max_coalesced_frames_irq, coalesce->rx_frames_irq);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_frames_low", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_max_coalesced_frames_low, coalesce->rx_frames_low);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "rx_frames_high", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.rx_max_coalesced_frames_high, coalesce->rx_frames_high);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_usecs", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.tx_coalesce_usecs, coalesce->tx_usecs);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_usecs_irq", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.tx_coalesce_usecs_irq, coalesce->tx_usecs_irq);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_usecs_low", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.tx_coalesce_usecs_low, coalesce->tx_usecs_low);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_usecs_high", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.tx_coalesce_usecs_high, coalesce->tx_usecs_high);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_frames", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.use_adaptive_tx_coalesce, coalesce->tx_frames);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_frames_irq", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.tx_max_coalesced_frames_irq, coalesce->tx_frames_irq);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_frames_low", NI_ETHTOOL_COALESCE_DEFAULT,
		&tmp.tx_max_coalesced_frames_low, coalesce->tx_frames_low);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCOALESCE,
			"coalesce", "tx_frames_high", NI_ETHTOOL_COALESCE_DEFAULT,
			&tmp.tx_max_coalesced_frames_high, coalesce->tx_frames_high);

	return 0;
}

static void
ni_ethtool_eee_init(ni_ethtool_eee_t *eee)
{
	if (eee) {
		eee->supported = NI_TRISTATE_DEFAULT;

		eee->status.enabled = NI_TRISTATE_DEFAULT;
		eee->status.active = NI_TRISTATE_DEFAULT;

		eee->speed.supported = NI_ETHTOOL_EEE_DEFAULT;
		eee->speed.advertised = NI_ETHTOOL_EEE_DEFAULT;
		eee->speed.lp_advertised = NI_ETHTOOL_EEE_DEFAULT;

		eee->tx_lpi.enabled = NI_TRISTATE_DEFAULT;
		eee->tx_lpi.timer = NI_ETHTOOL_EEE_DEFAULT;
	}
}

static int
ni_ethtool_get_eee(const char *ifname, ni_ethtool_eee_t *eee)
{
	struct ethtool_eee tmp;

	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GEEE, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.eee options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.eee options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			eee->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	eee->status.enabled = tmp.eee_enabled;
	eee->status.active = tmp.eee_active;

	eee->speed.supported = tmp.supported;
	eee->speed.advertised = tmp.advertised;
	eee->speed.lp_advertised = tmp.lp_advertised;

	eee->tx_lpi.enabled = tmp.tx_lpi_enabled;
	eee->tx_lpi.timer = tmp.tx_lpi_timer;

	return 0;
}

static int
ni_ethtool_set_eee(const char *ifname, ni_ethtool_eee_t *eee)
{
	struct ethtool_eee tmp;

	if (!eee || eee->supported == NI_TRISTATE_DISABLE)
		return -1;

	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GEEE, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.eee options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.eee options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			eee->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SEEE, "eee", "enable",
			NI_TRISTATE_ENABLE, &tmp.eee_enabled, eee->status.enabled);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SEEE, "eee", "advertise",
			NI_ETHTOOL_EEE_DEFAULT, &tmp.advertised, eee->speed.advertised);

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SEEE, "eee", "tx-lpi",
			NI_TRISTATE_ENABLE, &tmp.tx_lpi_enabled, eee->tx_lpi.enabled);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SEEE, "eee", "tx-timer",
			NI_ETHTOOL_EEE_DEFAULT, &tmp.tx_lpi_timer, eee->tx_lpi.timer);

	return 0;
}

static void
ni_ethtool_ring_init(ni_ethtool_ring_t *ring)
{
	if (ring) {
		ring->supported = NI_TRISTATE_DEFAULT;
		ring->tx	= NI_ETHTOOL_RING_DEFAULT;
		ring->rx	= NI_ETHTOOL_RING_DEFAULT;
		ring->rx_mini	= NI_ETHTOOL_RING_DEFAULT;
		ring->rx_jumbo	= NI_ETHTOOL_RING_DEFAULT;
	}
}

static int
ni_ethtool_get_ring(const char *ifname, ni_ethtool_ring_t *ring)
{
	struct ethtool_ringparam tmp;

	if (ring->supported == NI_TRISTATE_DISABLE)
		return -1;

	tmp.cmd = ETHTOOL_GRINGPARAM;
	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GRINGPARAM, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.ring options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.ring options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			ring->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	ring->tx = tmp.tx_pending;
	ring->rx = tmp.rx_pending;
	ring->rx_jumbo = tmp.rx_jumbo_pending;
	ring->rx_mini = tmp.rx_mini_pending;
	return 0;
}

static int
ni_ethtool_set_ring(const char *ifname, ni_ethtool_ring_t *ring)
{
	struct ethtool_ringparam tmp;

	if (ring->supported == NI_TRISTATE_DISABLE)
		return -1;

	tmp.cmd = ETHTOOL_GRINGPARAM;
	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GRINGPARAM, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.ring options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.ring options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			ring->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SRINGPARAM, "ring",
			"tx", tmp.tx_max_pending, &tmp.tx_pending, ring->tx);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SRINGPARAM, "ring",
			"rx", tmp.rx_max_pending, &tmp.rx_pending, ring->rx);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SRINGPARAM, "ring",
			"rx-jumbo", tmp.rx_jumbo_max_pending,
			&tmp.rx_jumbo_pending, ring->rx_jumbo);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SRINGPARAM, "ring",
				"rx-mini", tmp.rx_mini_max_pending,
				&tmp.rx_mini_pending, ring->rx_mini);

	return 0;
}

	static void
ni_ethtool_channels_init(ni_ethtool_channels_t *channels)
{
	if (channels) {
		channels->supported = NI_TRISTATE_DEFAULT;
		channels->tx	= NI_ETHTOOL_CHANNELS_DEFAULT;
		channels->rx	= NI_ETHTOOL_CHANNELS_DEFAULT;
		channels->other	= NI_ETHTOOL_CHANNELS_DEFAULT;
		channels->combined	= NI_ETHTOOL_CHANNELS_DEFAULT;
	}
}

static int
ni_ethtool_get_channels(const char *ifname, ni_ethtool_channels_t *channels)
{
	struct ethtool_channels tmp;

	if (channels->supported == NI_TRISTATE_DISABLE)
		return -1;

	tmp.cmd = ETHTOOL_GCHANNELS;
	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GCHANNELS, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.channels options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.channels options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			channels->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	channels->tx = tmp.tx_count;
	channels->rx = tmp.rx_count;
	channels->other = tmp.other_count;
	channels->combined = tmp.combined_count;
	return 0;
}

static int
ni_ethtool_set_channels(const char *ifname, ni_ethtool_channels_t *channels)
{
	struct ethtool_channels tmp;

	if (channels->supported == NI_TRISTATE_DISABLE)
		return -1;

	tmp.cmd = ETHTOOL_GCHANNELS;
	memset(&tmp, 0, sizeof(tmp));
	if (__ni_ethtool(ifname, ETHTOOL_GCHANNELS, &tmp) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: getting ethtool.channels options failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: getting ethtool.channels options failed: %m", ifname);

		if (errno != EOPNOTSUPP)
			channels->supported = NI_TRISTATE_DISABLE;
		return -1;
	}

	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCHANNELS, "channels",
			"tx", tmp.max_tx, &tmp.tx_count, channels->tx);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCHANNELS, "channels",
			"rx", tmp.max_rx, &tmp.rx_count, channels->rx);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCHANNELS, "channels",
			"other", tmp.max_other,
			&tmp.other_count, channels->other);
	ni_ethtool_set_uint_param(ifname, &tmp, ETHTOOL_SCHANNELS, "channels",
				"combined", tmp.max_combined,
				&tmp.combined_count, channels->combined);

	return 0;
}


void
__ni_system_ethernet_get(const char *ifname, ni_ethernet_t *ether)
{
	__ni_ethtool_get_wol(ifname, &ether->wol);
	__ni_ethtool_get_offload(ifname, &ether->offload);
	__ni_ethtool_get_permanent_address(ifname, &ether->permanent_address);
	__ni_ethtool_get_gset(ifname, ether);
	ni_ethtool_get_eee(ifname, &ether->eee);
	ni_ethtool_get_ring(ifname, &ether->ring);
	ni_ethtool_get_coalesce(ifname, &ether->coalesce);
	ni_ethtool_get_channels(ifname, &ether->channels);

	ni_ethtool_get_features(ifname);
}

/*
 * Write ethtool settings back to kernel
 */
void
__ni_system_ethernet_update(ni_netdev_t *dev, ni_ethernet_t *ether)
{
	/* should be not needed, but better safe than sorry. */
	if (!ni_netdev_device_is_ready(dev))
		return;

	__ni_system_ethernet_set(dev->name, ether);
	__ni_system_ethernet_refresh(dev);
}

static int
__ni_ethtool_get_gset(const char *ifname, ni_ethernet_t *ether)
{
	struct ethtool_cmd ecmd;
	int mapped;

	memset(&ecmd, 0, sizeof(ecmd));
	if (__ni_ethtool(ifname, ETHTOOL_GSET, &ecmd) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_GSET failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ETHTOOL_GSET failed: %m", ifname);
		return -1;
	}

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_speed_map, ethtool_cmd_speed(&ecmd));
	if (mapped >= 0)
		ether->link_speed = mapped;
	else
		ether->link_speed = ethtool_cmd_speed(&ecmd);

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_duplex_map, ecmd.duplex);
	if (mapped < 0)
		ni_warn("%s: unknown duplex setting %d", ifname, ecmd.duplex);
	else
		ether->duplex = mapped;

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_port_map, ecmd.port);
	if (mapped < 0)
		ni_warn("%s: unknown port setting %d", ifname, ecmd.port);
	else
		ether->port_type = mapped;

	ether->autoneg_enable = (ecmd.autoneg ? NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE);

	/* Not used yet:
	    phy_address
	    transceiver
	 */

	return 0;
}

/*
 * Based on ecmd.speed and ecmd.duplex, determine ecmd.advertising.
 */
static void
__ni_system_ethernet_set_advertising(const char *ifname, struct ethtool_cmd *ecmd)
{
	if (!ecmd)
		return;

	if (ecmd->speed == SPEED_10 && ecmd->duplex == DUPLEX_HALF)
		ecmd->advertising = ADVERTISED_10baseT_Half;
	else if (ecmd->speed == SPEED_10 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_10baseT_Full;
	else if (ecmd->speed == SPEED_100 &&
		ecmd->duplex == DUPLEX_HALF)
		ecmd->advertising = ADVERTISED_100baseT_Half;
	else if (ecmd->speed == SPEED_100 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_100baseT_Full;
	else if (ecmd->speed == SPEED_1000 &&
		ecmd->duplex == DUPLEX_HALF)
		ecmd->advertising = ADVERTISED_1000baseT_Half;
	else if (ecmd->speed == SPEED_1000 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_1000baseT_Full;
	else if (ecmd->speed == SPEED_2500 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_2500baseX_Full;
	else if (ecmd->speed == SPEED_10000 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_10000baseT_Full;
	else
		/* auto negotiate without forcing,
		 * all supported speeds will be assigned below
		 */
		ecmd->advertising = 0;

	if (ecmd->autoneg && ecmd->advertising == 0) {
		/* Auto negotiation enabled, but with
		 * unspecified speed and duplex: enable all
		 * supported speeds and duplexes.
		 */
		ecmd->advertising = (ecmd->advertising &
				~ALL_ADVERTISED_MODES) |
			(ALL_ADVERTISED_MODES &
				ecmd->supported);
		/* If driver supports unknown flags, we cannot
		 * be sure that we enable all link modes.
		 */
		if ((ecmd->supported & ALL_ADVERTISED_FLAGS) != ecmd->supported) {
			ni_error("%s: Driver supports one or more unknown flags",
				ifname);
		}
	} else if (ecmd->advertising > 0) {
		/* Enable all requested modes. */
		ecmd->advertising = (ecmd->advertising & ~ALL_ADVERTISED_MODES) |
			ecmd->advertising;
	}
}

static int
__ni_ethtool_set_sset(const char *ifname, const ni_ethernet_t *ether)
{
	struct ethtool_cmd ecmd;
	int mapped;

	memset(&ecmd, 0, sizeof(ecmd));
	if (__ni_ethtool(ifname, ETHTOOL_GSET, &ecmd) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_GSET failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: ETHTOOL_GSET failed: %m", ifname);
		return -1;
	}

	if (ether->link_speed) {
		mapped = __ni_wicked_to_ethtool(__ni_ethtool_speed_map, ether->link_speed);
		if (mapped < 0)
			mapped = ether->link_speed;
		ethtool_cmd_speed_set(&ecmd, mapped);
	}

	if (ether->duplex != NI_ETHERNET_DUPLEX_DEFAULT) {
		mapped = __ni_wicked_to_ethtool(__ni_ethtool_duplex_map, ether->duplex);
		if (mapped >= 0)
			ecmd.duplex = mapped;
	}

	if (ether->port_type != NI_ETHERNET_PORT_DEFAULT) {
		mapped = __ni_wicked_to_ethtool(__ni_ethtool_port_map, ether->port_type);
		if (mapped >= 0)
			ecmd.port = mapped;
	}

	switch (ether->autoneg_enable) {
	case NI_TRISTATE_ENABLE:
		ecmd.autoneg = 1;
		break;
	case NI_TRISTATE_DISABLE:
		ecmd.autoneg = 0;
		break;
	default: ;
	}

	/* Not used yet:
	    phy_address
	    transceiver
	 */

	__ni_system_ethernet_set_advertising(ifname, &ecmd);

	if (__ni_ethtool(ifname, ETHTOOL_SSET, &ecmd) < 0) {
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ETHTOOL_SSET failed: %m", ifname);
		else
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IFCONFIG,
				"%s: ETHTOOL_SSET failed: %m", ifname);
		return -1;
	}

	return 0;
}

void
__ni_system_ethernet_set(const char *ifname, ni_ethernet_t *ether)
{
	__ni_ethtool_set_wol(ifname, &ether->wol);
	__ni_ethtool_set_offload(ifname, &ether->offload);
	__ni_ethtool_set_sset(ifname, ether);
	ni_ethtool_set_eee(ifname, &ether->eee);
	ni_ethtool_set_ring(ifname, &ether->ring);
	ni_ethtool_set_coalesce(ifname, &ether->coalesce);
	ni_ethtool_set_channels(ifname, &ether->channels);
}
