/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include <stdint.h>

struct mbim_message;
struct mbim_message_iter;

struct mbim_message_iter {
	const char *sig_start;
	uint8_t sig_len;
	uint8_t sig_pos;
	const struct iovec *iov;
	uint32_t n_iov;
	uint32_t cur_iov;
	size_t cur_iov_offset;
	size_t len;
	size_t pos;
	size_t base_offset;
	uint32_t n_elem;
	char container_type;
};

struct mbim_message *mbim_message_new(const uint8_t *uuid, uint32_t cid);
struct mbim_message *mbim_message_ref(struct mbim_message *msg);
void mbim_message_unref(struct mbim_message *msg);

bool mbim_message_iter_next_entry(struct mbim_message_iter *iter, ...);