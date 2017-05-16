/*
 *	DHCP Unique Identifier (DUID) utilities
 *
 *	Copyright (C) 2012-2017 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *              Nirmoy Das <ndas@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/util.h>
#include <wicked/xml.h>

#include "duid.h"
#include "util_priv.h"
#include "buffer.h"

#ifndef NI_MACHINE_ID_FILE
#define NI_MACHINE_ID_FILE		"/etc/machine-id"
#endif
#ifndef NI_DMI_PRODUCT_UUID_FILE
#define NI_DMI_PRODUCT_UUID_FILE	"/sys/devices/virtual/dmi/id/product_uuid";
#endif

#define NI_CONFIG_DEFAULT_DUID_NODE	"duid"
#define NI_CONFIG_DEFAULT_DUID_FILE	"duid.xml"
#define NI_CONFIG_DEFAULT_DUID_DEVICE	"device"


/*
 * compiler (gcc) specific ...
 */
#define PACKED __attribute__((__packed__))

/*
 * DUID typed data
 */
typedef union ni_duid_data {
	ni_duid_uuid_t		uuid;
	ni_duid_llt_t		llt;
	ni_duid_ll_t		ll;
	ni_duid_en_t		en;
} PACKED ni_duid_data_t;

static const ni_intmap_t	ni_duid_type_names[] = {
	{ "en",			NI_DUID_TYPE_EN		},
	{ "ll",			NI_DUID_TYPE_LL		},
	{ "llt",		NI_DUID_TYPE_LLT	},
	{ "uuid",		NI_DUID_TYPE_UUID	},

	{ NULL,			0			}
};

const char *
ni_duid_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_duid_type_names);
}

ni_bool_t
ni_duid_type_by_name(const char *name, unsigned int *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_duid_type_names, type) < 0)
		return FALSE;
	return TRUE;
}

ni_bool_t
ni_duid_init_llt(ni_opaque_t *duid, unsigned short arp_type, const void *hwaddr, size_t len)
{
	ni_duid_data_t *data;
	time_t		now;
	uint64_t	u64;

	memset(duid, 0, sizeof(*duid));
	if (!len)
		return FALSE;

	if (time(&now) == (time_t)-1)
		return FALSE;

	if ((sizeof(ni_duid_llt_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_llt_t);

	duid->len = sizeof(ni_duid_llt_t) + len;

	u64 = (uint64_t)(now - NI_DUID_TIME_EPOCH);
	data = (ni_duid_data_t *)&duid->data;
	data->llt.type = htons((uint16_t)NI_DUID_TYPE_LLT);
	data->llt.hwtype = htons(arp_type);
	data->llt.v6time = htonl((uint32_t)(u64 & 0xffffffff));
	memcpy(data->llt.hwaddr, hwaddr, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_ll (ni_opaque_t *duid, unsigned short hwtype, const void *hwaddr, size_t len)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (!len)
		return FALSE;

	if ((sizeof(ni_duid_ll_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_ll_t);

	duid->len = sizeof(ni_duid_ll_t) + len;

	data = (ni_duid_data_t *)&duid->data;
	data->ll.type = htons((uint16_t)NI_DUID_TYPE_LL);
	data->ll.hwtype = htons(hwtype);
	memcpy(data->ll.hwaddr, hwaddr, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_en (ni_opaque_t *duid, unsigned int enumber, const void *identifier, size_t len)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (!len || !enumber)
		return FALSE;

	if ((sizeof(ni_duid_en_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_en_t);

	duid->len = sizeof(ni_duid_en_t) + len;

	data = (ni_duid_data_t *)&duid->data;
	data->en.type = htons((uint16_t)NI_DUID_TYPE_EN);
	data->en.enterprise = htonl(enumber);
	memcpy(data->en.identifier, identifier, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_uuid(ni_opaque_t *duid, const ni_uuid_t *uuid)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (ni_uuid_is_null(uuid))
		return FALSE;

	duid->len = sizeof(ni_duid_uuid_t);

	data = (ni_duid_data_t *)&duid->data;
	data->uuid.type = htons((uint16_t)NI_DUID_TYPE_UUID);
	memcpy(&data->uuid.uuid, uuid, sizeof(data->uuid.uuid));
	return TRUE;
}

ni_bool_t
ni_duid_copy(ni_opaque_t *duid, const ni_opaque_t *src)
{
	if (!duid || !src)
		return FALSE;

	ni_duid_clear(duid);
	if (src->len)
		ni_opaque_set(duid, src->data, src->len);
	return TRUE;
}

void
ni_duid_clear(ni_opaque_t *duid)
{
	memset(duid, 0, sizeof(*duid));
}

ni_bool_t
ni_duid_parse_hex(ni_opaque_t *duid, const char *hex)
{
	int len;

	len = ni_parse_hex(hex, duid->data, sizeof(duid->data));
	if (len < 0 || (size_t)len <= sizeof(ni_duid_ll_t))
		return FALSE;

	return (duid->len = len) > 0;
}

const char *
ni_duid_format_hex(char **hex, const ni_opaque_t *duid)
{
	ni_string_free(hex);

	if (duid->len > 0) {
		size_t len = duid->len * 3 + 1;
		*hex = xcalloc(1, len);
		ni_format_hex(duid->data, duid->len, *hex, len);
	}
	return *hex;
}

int
ni_duid_load(ni_opaque_t *duid, const char *filename, const char *name)
{
	char path[PATH_MAX];
	xml_node_t *xml = NULL;
	xml_node_t *node;
	FILE *fp;
	int rv;

	if (ni_string_empty(name))
		name = NI_CONFIG_DEFAULT_DUID_NODE;

	if (!filename) {
		/* On root-fs, state dir used as fallback */
		snprintf(path, sizeof(path), "%s/%s",
				ni_config_statedir(),
				NI_CONFIG_DEFAULT_DUID_FILE);
		filename = path;

		/* Then the proper, reboot persistent dir */
		if ((fp = fopen(filename, "re")) == NULL) {
			snprintf(path, sizeof(path), "%s/%s",
					ni_config_storedir(),
					NI_CONFIG_DEFAULT_DUID_FILE);
			filename = path;

			fp = fopen(filename, "re");
		}
	} else {
		fp = fopen(filename, "re");
	}

	if (fp == NULL) {
		if (errno != ENOENT)
			ni_error("unable to open %s for reading: %m", filename);
		return -1;
	}
	xml = xml_node_scan(fp, NULL);
	fclose(fp);

	if (xml == NULL) {
		ni_error("%s: unable to parse xml file", filename);
		return -1;
	}

	if (xml->name == NULL)
		node = xml->children;
	else
		node = xml;

	if (!node || !ni_string_eq(node->name, name)) {
		ni_error("%s: does not contain %s", filename, name);
		xml_node_free(xml);
		return -1;
	}

	rv = 0;
	if (!node->cdata || !ni_duid_parse_hex(duid, node->cdata)) {
		ni_error("%s: unable to parse %s file", filename, name);
		rv = -1;
	}

	xml_node_free(xml);
	return rv;
}

static int
__ni_duid_save_node(xml_node_t *node, const char *filename)
{
	char tempname[PATH_MAX] = {'\0'};
	FILE *fp = NULL;
	int rv = -1;
	int fd;

	if (!node || !node->name || !filename)
		return rv;

	snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
	if ((fd = mkstemp(tempname)) < 0) {
		if (errno == EROFS)
			return 1;

		ni_error("%s: unable create temporary file for writing: %m", filename);
		goto failed;
	}

	if ((fp = fdopen(fd, "we")) == NULL) {
		ni_error("%s: unable to open file for writing: %m", filename);
		goto failed;
	}

	if (xml_node_print(node, fp) < 0) {
		ni_error("%s: unable to write %s representation",
				filename, node->name);
		goto failed;
	}

	if ((rv = rename(tempname, filename)) != 0) {
		ni_error("%s: unable to rename temporary file '%s': %m",
				filename, tempname);
		goto failed;
	}

failed:
	if (fp != NULL)
		fclose(fp);
	else if (fd >= 0)
		close(fd);
	if (tempname[0])
		unlink(tempname);
	return rv;
}

int
ni_duid_save(const ni_opaque_t *duid, const char *filename, const char *name)
{
	char path[PATH_MAX] = {'\0'};
	xml_node_t *node;
	int rv = -1;

	if (!duid || !duid->len) {
		ni_error("BUG: Refusing to save empty duid");
		return -1;
	}

	if (ni_string_empty(name))
		name = NI_CONFIG_DEFAULT_DUID_NODE;

	if ((node = xml_node_new(name, NULL)) == NULL) {
		ni_error("Unable to create %s xml node: %m", name);
		return -1;
	}
	ni_duid_format_hex(&node->cdata, duid);

	if (!filename) {
		snprintf(path, sizeof(path), "%s/%s",
				ni_config_storedir(),
				NI_CONFIG_DEFAULT_DUID_FILE);
		filename = path;
	}

	/* Try reboot persistent store dir */
	rv = __ni_duid_save_node(node, filename);
	if (filename == path) {
		if (rv == 0) {
			snprintf(path, sizeof(path), "%s/%s",
					ni_config_statedir(),
					NI_CONFIG_DEFAULT_DUID_FILE);

			/* Fallback in state dir is obsolete */
			unlink(path);
		} else
		if (rv > 0) {
			snprintf(path, sizeof(path), "%s/%s",
					ni_config_statedir(),
					NI_CONFIG_DEFAULT_DUID_FILE);

			/* Then try state dir as fallback */
			rv = __ni_duid_save_node(node, path);
		}
	}

	xml_node_free(node);
	return rv > 0 ? -1 : rv;
}

static ni_bool_t
ni_duid_create_parse_hwaddr(ni_hwaddr_t *hwa, unsigned short hwtype, const char *hwaddr)
{
	if (!hwa || !ni_link_address_length(hwtype) || ni_string_empty(hwaddr))
		return FALSE;

	if (ni_link_address_parse(hwa, hwtype, hwaddr) != 0)
		return FALSE;

	return !ni_link_address_is_invalid(hwa); /* all zero and brd */
}

ni_bool_t
ni_duid_create_ll(ni_opaque_t *duid, const char *hwtype, const char *hwaddr)
{
	unsigned int type;
	ni_hwaddr_t hwa;

	if (!duid || (type = (unsigned int)ni_arphrd_name_to_type(hwtype)) == -1U)
		return FALSE;

	if (!ni_duid_create_parse_hwaddr(&hwa, type, hwaddr))
		return FALSE;

	return ni_duid_init_llt(duid, hwa.type, hwa.data, hwa.len);
}

ni_bool_t
ni_duid_create_llt(ni_opaque_t *duid, const char *hwtype, const char *hwaddr)
{
	unsigned int type;
	ni_hwaddr_t hwa;

	if (!duid || (type = (unsigned int)ni_arphrd_name_to_type(hwtype)) == -1U)
		return FALSE;

	if (!ni_duid_create_parse_hwaddr(&hwa, type, hwaddr))
		return FALSE;

	return ni_duid_init_llt(duid, hwa.type, hwa.data, hwa.len);
}

ni_bool_t
ni_duid_create_en(ni_opaque_t *duid, const char *enumber, const char *identifier)
{
	ni_opaque_t id;
	unsigned int nr;

	if (!duid || ni_string_empty(identifier))
		return FALSE;

	if (ni_parse_uint(enumber, &nr, 0) < 0 || !nr)
		return FALSE;

	id.len = ni_parse_hex_data(identifier, id.data, sizeof(duid->data), ":");
	if ((ssize_t)id.len <= 0 || id.len > NI_DUID_DATA_LEN - sizeof(uint32_t))
		return FALSE;

	return ni_duid_init_en(duid, nr, id.data, id.len);
}

ni_bool_t
ni_duid_create_uuid_string(ni_opaque_t *duid, const char *string)
{
	ni_uuid_t uuid;

	if (!duid || ni_uuid_parse(&uuid, string) < 0)
		return FALSE;

	return ni_duid_init_uuid(duid, &uuid);
}

ni_bool_t
ni_duid_create_uuid_machine_id(ni_opaque_t *duid, const char *filename)
{
	char line[64] = {'\0'};
	ni_uuid_t uuid;
	ssize_t len;
	FILE *file;

	if (ni_string_empty(filename))
		filename = NI_MACHINE_ID_FILE;

	if (!duid || !(file = fopen(filename, "re")))
		return FALSE;

	if (fgets(line, sizeof(line)-1, file)) {
		line[strcspn(line, " \t\n")] = '\0';
		fclose(file);
	} else {
		fclose(file);
		return FALSE;
	}

	len = ni_parse_hex_data(line, uuid.octets, sizeof(uuid.octets), "");
	if (len != sizeof(uuid.octets))
		return FALSE;

	return ni_duid_init_uuid(duid, &uuid);
}

ni_bool_t
ni_duid_create_uuid_dmi_product_id(ni_opaque_t *duid, const char *filename)
{
	char line[64] = {'\0'};
	ni_uuid_t uuid;
	FILE *file;

	if (ni_string_empty(filename))
		filename = NI_DMI_PRODUCT_UUID_FILE;

	if (!duid || !(file = fopen(filename, "re")))
		return FALSE;

	if (fgets(line, sizeof(line)-1, file)) {
		line[strcspn(line, " \t\n")] = '\0';
		fclose(file);
	} else {
		fclose(file);
		return FALSE;
	}

	if (ni_uuid_parse(&uuid, line) < 0)
		return FALSE;

	return ni_duid_init_uuid(duid, &uuid);
}

struct ni_duid_map {
	xml_document_t *doc;

	int		fd;
	char *		file;
	struct flock	flock;
};

static ni_duid_map_t *			ni_duid_map_new(void);
static ni_bool_t			ni_duid_map_lock(ni_duid_map_t *);
static ni_bool_t			ni_duid_map_unlock(ni_duid_map_t *);

static ni_duid_map_t *
ni_duid_map_new(void)
{
	ni_duid_map_t *map;

	map = calloc(1, sizeof(*map));
	if (map) {
		map->fd = -1;
		map->flock.l_type = F_UNLCK;
	}
	return map;
}

void
ni_duid_map_free(ni_duid_map_t *map)
{
	if (map) {
		if (map->fd >= 0) {
			ni_duid_map_unlock(map);
			close(map->fd);
			map->fd = -1;
		}
		xml_document_free(map->doc);
		ni_string_free(&map->file);
		free(map);
	}
}

static ni_bool_t
ni_duid_map_lock(ni_duid_map_t *map)
{
	if (!map || map->fd < 0)
		return FALSE;

	map->flock.l_type   = F_WRLCK;
	map->flock.l_whence = SEEK_SET;
	map->flock.l_start  = 0;
	map->flock.l_len    = 0;
	map->flock.l_pid    = 0;

	if (fcntl(map->fd,  F_SETLKW, &map->flock) < 0) {
		map->flock.l_type = F_UNLCK;
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_duid_map_unlock(ni_duid_map_t *map)
{
	if (!map || map->fd < 0)
		return FALSE;

	if (map->flock.l_type == F_UNLCK)
		return TRUE;

	map->flock.l_type   = F_UNLCK;
	map->flock.l_whence = SEEK_SET;
	map->flock.l_start  = 0;
	map->flock.l_len    = 0;
	map->flock.l_pid    = 0;

	if (fcntl(map->fd,  F_SETLKW, &map->flock) < 0)
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_duid_map_open(ni_duid_map_t *map)
{
	int flags = O_CLOEXEC | O_NOCTTY | O_RDWR | O_CREAT;
	int mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;

	if (!map || map->fd >= 0 || ni_string_empty(map->file))
		return FALSE;

	map->fd = open(map->file, flags, mode);
	if (map->fd < 0)
		return FALSE;
	return TRUE;
}

ni_bool_t
ni_duid_map_set_default_file(char **filename)
{
	return ni_string_printf(filename, "%s/%s",
			ni_config_storedir(),
			NI_CONFIG_DEFAULT_DUID_FILE) != NULL;
}

ni_bool_t
ni_duid_map_set_fallback_file(char **filename)
{
	return ni_string_printf(filename, "%s/%s",
			ni_config_statedir(),
			NI_CONFIG_DEFAULT_DUID_FILE) != NULL;
}

ni_duid_map_t *
ni_duid_map_load(const char *filename)
{
	ni_duid_map_t *map;
	ni_buffer_t buff;
	struct stat stb;
	ssize_t len;

	if (!(map = ni_duid_map_new())) {
		ni_error("unable to allocate memory for duid map: %m");
		return NULL;
	}

	if (filename) {
		if (!ni_string_dup(&map->file, filename)) {
			ni_error("unable to copy custom duid map file name (%s): %m", filename);
			goto failure;
		}

		if (!ni_duid_map_open(map)) {
			ni_error("unable to open duid map file name (%s): %m", map->file);
			goto failure;
		}
	} else {
		if (!ni_duid_map_set_default_file(&map->file)) {
			ni_error("unable to construct default duid map file name: %m");
			goto failure;
		}

		if (!ni_duid_map_open(map)) {
			ni_debug_readwrite("unable to open duid map file name (%s): %m", map->file);

			if (!ni_duid_map_set_fallback_file(&map->file)) {
				ni_error("unable to construct fallback duid map file name: %m");
				goto failure;
			}

			if (!ni_duid_map_open(map)) {
				ni_error("unable to open duid map file name (%s): %m", map->file);
				goto failure;
			}
		}
	}

	if (!ni_duid_map_lock(map)) {
		ni_error("unable to lock duid map file name (%s): %m", map->file);
		goto failure;
	}

	if (fstat(map->fd, &stb) < 0)
		stb.st_size = BUFSIZ;

	ni_buffer_init_dynamic(&buff, stb.st_size + 1);
	do {
		if (!ni_buffer_tailroom(&buff))
			ni_buffer_ensure_tailroom(&buff, BUFSIZ);

		do {
			len = read(map->fd, ni_buffer_tail(&buff), ni_buffer_tailroom(&buff));
			if (len > 0)
				ni_buffer_push_tail(&buff, len);
		} while (len < 0 && errno == EINTR);
	} while (len > 0);

	map->doc = xml_document_from_buffer(&buff, map->file);
	ni_buffer_destroy(&buff);
	if (!map->doc)
		map->doc = xml_document_new();

	return map;
failure:
	ni_duid_map_free(map);
	return NULL;
}

ni_bool_t
ni_duid_map_save(ni_duid_map_t *map)
{
	char *data = NULL;
	size_t off, len;
	ssize_t ret;

	if (!map || map->fd < 0)
		return FALSE;

	if (lseek(map->fd, 0, SEEK_SET) < 0)
		return FALSE;

	if (ftruncate(map->fd, 0) < 0)
		return FALSE;

	if (map->doc && map->doc->root)
		data = xml_node_sprint(map->doc->root);

	len = ni_string_len(data);
	off = 0;
	ret = 0;
	while (len > off) {
		ret = write(map->fd, data + off, len - off);
		if (ret < 0 && errno != EINTR)
			break;
		else
		if (ret > 0)
			off += ret;
	}
	free(data);

	return ret < 0 ? FALSE : TRUE;
}

static xml_node_t *
ni_duid_map_root_node(ni_duid_map_t *map)
{
	if (!map || !map->doc)
		return NULL;
	return xml_document_root(map->doc);
}

static xml_node_t *
ni_duid_map_next_node(const xml_node_t *root, const xml_node_t *last)
{
	return xml_node_get_next_child(root, NI_CONFIG_DEFAULT_DUID_NODE, last);
}

ni_bool_t
ni_duid_map_get_duid(ni_duid_map_t *map, const char *name, const char **duid)
{
	xml_node_t *root, *node = NULL;
	const char *attr;

	if (!(root = ni_duid_map_root_node(map)) || !duid)
		return FALSE;

	while ((node = ni_duid_map_next_node(root, node))) {
		attr = xml_node_get_attr(node, NI_CONFIG_DEFAULT_DUID_DEVICE);
		if (ni_string_empty(node->cdata))
			continue;
		if (!ni_string_eq(name, attr))
			continue;

		*duid = node->cdata;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_duid_map_get_name(ni_duid_map_t *map, const char *duid, const char **name)
{
	xml_node_t *root, *node = NULL;

	if (!(root = ni_duid_map_root_node(map)) || !name)
		return FALSE;

	while ((node = ni_duid_map_next_node(root, node))) {
		if (ni_string_empty(node->cdata))
			continue;
		if (!ni_string_eq(duid, node->cdata))
			continue;

		*name = xml_node_get_attr(node, NI_CONFIG_DEFAULT_DUID_DEVICE);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_duid_map_set(ni_duid_map_t *map, const char *name, const char *duid)
{
	xml_node_t *root, *node = NULL;
	const char *attr;

	/* TODO: parse duid string to not store crap? */
	if (!(root = ni_duid_map_root_node(map)) || ni_string_empty(duid))
		return FALSE;

	while ((node = ni_duid_map_next_node(root, node))) {
		attr = xml_node_get_attr(node, NI_CONFIG_DEFAULT_DUID_DEVICE);
		if (!ni_string_eq(name, attr))
			continue;

		xml_node_set_cdata(node, duid);
		return TRUE;
	}
	if ((node = xml_node_new(NI_CONFIG_DEFAULT_DUID_NODE, root))) {
		if (!ni_string_empty(name))
			xml_node_add_attr(node, NI_CONFIG_DEFAULT_DUID_DEVICE, name);
		xml_node_set_cdata(node, duid);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_duid_map_del(ni_duid_map_t *map, const char *name)
{
	xml_node_t *root, *node = NULL;
	const char *attr;

	if (!(root = ni_duid_map_root_node(map)))
		return FALSE;

	while ((node = ni_duid_map_next_node(root, node))) {
		attr = xml_node_get_attr(node, NI_CONFIG_DEFAULT_DUID_DEVICE);
		if (!ni_string_eq(name, attr))
			continue;

		xml_node_detach(node);
		xml_node_free(node);
		return TRUE;
	}
	return FALSE;
}

