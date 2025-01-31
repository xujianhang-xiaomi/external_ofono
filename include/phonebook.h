/*
 *
 *  oFono - Open Telephony stack for Linux
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __OFONO_PHONEBOOK_H
#define __OFONO_PHONEBOOK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ofono/types.h>

struct ofono_phonebook;

struct fdn_entry {
	int entry;
	char *name;
	char *number;
};

typedef void (*ofono_phonebook_cb_t)(const struct ofono_error *error,
					void *data);

typedef void (*ofono_phonebook_update_cb_t)(const struct ofono_error *error,
					int record, void *data);

/* Export entries reports results through ofono_phonebook_entry, if an error
 * occurs, ofono_phonebook_entry should not be called
 */
struct ofono_phonebook_driver {
	const char *name;
	int (*probe)(struct ofono_phonebook *pb, unsigned int vendor,
			void *data);
	void (*remove)(struct ofono_phonebook *pb);
	void (*export_entries)(struct ofono_phonebook *pb, const char *storage,
				ofono_phonebook_cb_t cb, void *data);
	void (*read_fdn_entries)(struct ofono_phonebook *pb,
				ofono_phonebook_cb_t cb, void *data);
	void (*insert_fdn_entry)(struct ofono_phonebook *pb, const char *new_name,
				const char *new_number, const char *pin2,
				ofono_phonebook_update_cb_t cb, void *data);
	void (*update_fdn_entry)(struct ofono_phonebook *pb,
				int record, const char *identifier,
				const char *new_number, const char *pin2,
				ofono_phonebook_update_cb_t cb, void *data);
	void (*delete_fdn_entry)(struct ofono_phonebook *pb,
				int record, const char *pin2,
				ofono_phonebook_update_cb_t cb, void *data);
};

void ofono_phonebook_entry(struct ofono_phonebook *pb, int index,
				const char *number, int type,
				const char *text, int hidden,
				const char *group,
				const char *adnumber, int adtype,
				const char *secondtext, const char *email,
				const char *sip_uri, const char *tel_uri);

int ofono_phonebook_driver_register(const struct ofono_phonebook_driver *d);
void ofono_phonebook_driver_unregister(const struct ofono_phonebook_driver *d);

struct ofono_phonebook *ofono_phonebook_create(struct ofono_modem *modem,
							unsigned int vendor,
							const char *driver,
							void *data);

void ofono_phonebook_register(struct ofono_phonebook *pb);
void ofono_phonebook_remove(struct ofono_phonebook *pb);

void ofono_phonebook_set_data(struct ofono_phonebook *pb, void *data);
void *ofono_phonebook_get_data(struct ofono_phonebook *pb);
void ofono_phonebook_set_fdn_data(struct ofono_phonebook *pb, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_PHONEBOOK_H */
