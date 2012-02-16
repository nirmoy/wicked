/*
 * Address configuration modes for netinfo
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ADDRCONF_H__
#define __WICKED_ADDRCONF_H__

#include <wicked/types.h>
#include <wicked/constants.h>

/*
 * DHCP configuration info
 */
enum {
	NI_ADDRCONF_UPDATE_DEFAULT_ROUTE,
	NI_ADDRCONF_UPDATE_HOSTNAME,
	NI_ADDRCONF_UPDATE_HOSTSFILE,
	NI_ADDRCONF_UPDATE_SYSLOG,
	NI_ADDRCONF_UPDATE_RESOLVER,
	NI_ADDRCONF_UPDATE_NIS,
	NI_ADDRCONF_UPDATE_NTP,
	NI_ADDRCONF_UPDATE_NETBIOS,
	NI_ADDRCONF_UPDATE_SLP,

	__NI_ADDRCONF_UPDATE_MAX,
};


struct ni_addrconf_request {
	ni_addrconf_request_t *	next;

	char *			owner;
	ni_uuid_t		uuid;

	/* Options what to update based on the info received from 
	 * the DHCP server. */
	unsigned int		update;
};

/*
 * Leases obtained through a dynamic addrconf protocol,
 * such as DHCP, DHCPv6, IPv4LL, or IBFT.
 */
enum {
	NI_ADDRCONF_STATE_NONE,
	NI_ADDRCONF_STATE_REQUESTING,
	NI_ADDRCONF_STATE_GRANTED,
	NI_ADDRCONF_STATE_RELEASING,
	NI_ADDRCONF_STATE_RELEASED,
	NI_ADDRCONF_STATE_FAILED,

	__NI_ADDRCONF_STATE_MAX
};

struct ni_addrconf_lease {
	ni_addrconf_lease_t *	next;

	ni_addrconf_mode_t	type;
	int			family;
	char *			owner;

	ni_uuid_t		uuid;
	int			state;

	unsigned int		time_acquired;

	unsigned int		update;

	char *			hostname;
	ni_address_t *		addrs;
	ni_route_t *		routes;

	/* Services discovered through the DHCP and similar */
	ni_nis_info_t *		nis;
	ni_resolver_info_t *	resolver;

	ni_string_array_t	log_servers;
	ni_string_array_t	ntp_servers;
	ni_string_array_t	netbios_name_servers;
	ni_string_array_t	netbios_dd_servers;
	char *			netbios_domain;
	char *			netbios_scope;
	ni_string_array_t	slp_servers;
	ni_string_array_t	slp_scopes;
	ni_string_array_t	sip_servers;
	ni_string_array_t	lpr_servers;

	/* Information specific to some addrconf protocol */
	union {
	    struct ni_addrconf_lease_dhcp {
		struct in_addr		serveraddress;
		char			servername[64];
		char			client_id[64];

		struct in_addr		address;
		struct in_addr		netmask;
		struct in_addr		broadcast;
		uint16_t		mtu;

		uint32_t		lease_time;
		uint32_t		renewal_time;
		uint32_t		rebind_time;

		char *			message;
		char *			rootpath;
	    } dhcp;
	};
};

enum ni_lease_event {
	NI_EVENT_LEASE_ACQUIRED,
	NI_EVENT_LEASE_RELEASED,
	NI_EVENT_LEASE_LOST
};

#define NI_ADDRCONF_MASK(mode)		(1 << (mode))
#define NI_ADDRCONF_TEST(mask, mode)	!!((mask) & NI_ADDRCONF_MASK(mode))

static inline void
ni_afinfo_addrconf_enable(struct ni_afinfo *afi, ni_addrconf_mode_t mode)
{
	afi->addrconf |= NI_ADDRCONF_MASK(mode);
}

static inline void
ni_afinfo_addrconf_disable(struct ni_afinfo *afi, ni_addrconf_mode_t mode)
{
	afi->addrconf &= ~NI_ADDRCONF_MASK(mode);
}

static inline int
ni_afinfo_addrconf_test(const struct ni_afinfo *afi, ni_addrconf_mode_t mode)
{
	return !!(afi->addrconf & NI_ADDRCONF_MASK(mode));
}

static inline void
ni_addrconf_set_update(ni_addrconf_request_t *req, unsigned int target)
{
	req->update |= (1 << target);
}

static inline int
ni_addrconf_should_update(const ni_addrconf_request_t *req, unsigned int target)
{
	return req->update & (1 << target);
}

static inline void
__ni_addrconf_set_update(unsigned int *mask_p, unsigned int target)
{
	*mask_p |= (1 << target);
}

static inline void
__ni_addrconf_clear_update(unsigned int *mask_p, unsigned int target)
{
	*mask_p &= ~(1 << target);
}

static inline int
__ni_addrconf_should_update(unsigned int mask, unsigned int target)
{
	return mask & (1 << target);
}

extern ni_afinfo_t *	ni_afinfo_new(int family);
extern void		ni_afinfo_free(ni_afinfo_t *);

extern ni_addrconf_request_t *ni_addrconf_request_new(const char *owner);
extern void		ni_addrconf_request_free(ni_addrconf_request_t *);
extern int		ni_addrconf_request_equal(const ni_addrconf_request_t *, const ni_addrconf_request_t *);

extern ni_addrconf_lease_t *ni_addrconf_lease_new(int type, int family);
extern void		ni_addrconf_lease_destroy(ni_addrconf_lease_t *);
extern void		ni_addrconf_lease_free(ni_addrconf_lease_t *);
extern void		ni_addrconf_lease_list_destroy(ni_addrconf_lease_t **list);

static inline int
ni_addrconf_lease_is_valid(const ni_addrconf_lease_t *lease)
{
	return lease && lease->state == NI_ADDRCONF_STATE_GRANTED;
}

extern int		ni_addrconf_lease_file_write(const char *, ni_addrconf_lease_t *);
extern ni_addrconf_lease_t *ni_addrconf_lease_file_read(const char *, int, int);
extern void		ni_addrconf_lease_file_remove(const char *, int, int);
extern int		ni_addrconf_request_file_write(const char *, ni_addrconf_request_t *);
extern ni_addrconf_request_t *ni_addrconf_request_file_read(const char *, int, int);
extern void		ni_addrconf_request_file_remove(const char *, int, int);

extern unsigned int	ni_system_update_capabilities(void);
extern int		ni_system_update_from_lease(ni_netconfig_t *, ni_interface_t *, const ni_addrconf_lease_t *);

#endif /* __WICKED_ADDRCONF_H__ */
