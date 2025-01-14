/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013 Canonical Ltd.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>
#include <ofono/types.h>

#include <gril/gril.h>

#include "ofono.h"
#include "common.h"

#include "rilmodem.h"

#define NUM_ACTIVATION_RETRIES 5
#define TIME_BETWEEN_ACT_RETRIES_S 2
#define NUM_DEACTIVATION_RETRIES 4
#define TIME_BETWEEN_DEACT_RETRIES_S 2

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	GRil *ril;
	unsigned vendor;
	gint active_rild_cid;
	enum state state;
	guint call_list_id;
	char *apn;
	int deact_retries;
	int act_retries;
	guint retry_deact_id;
	guint retry_act_id;
	struct cb_data *deact_retry_cbd;
	struct cb_data *active_retry_cbd;
	guint reset_ev_id;
};

static void ril_gprs_context_deactivate_primary(struct ofono_gprs_context *gc,
						unsigned int id,
						ofono_gprs_context_cb_t cb,
						void *data);
static void ril_deactivate_data_call_cb(struct ril_msg *message,
					gpointer user_data);
static gboolean retry_activate(gpointer user_data);
static gboolean retry_activate_abort(struct ofono_gprs_context *gc);
static int get_next_activate_retry_delay(struct gprs_context_data *gcd,
					int fail_cause, int raw_delay);

static void set_context_disconnected(struct gprs_context_data *gcd)
{
	DBG("");

	gcd->active_rild_cid = -1;
	gcd->state = STATE_IDLE;
	g_free(gcd->apn);
	gcd->apn = NULL;
}

static void disconnect_context(struct ofono_gprs_context *gc)
{
	ril_gprs_context_deactivate_primary(gc, 0, NULL, NULL);
}

static void ril_gprs_context_call_list_changed(struct ril_msg *message,
						gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct parcel rilp;
	int num_calls;
	int cid;
	int active;
	int i;
	int used_cid = gcd->active_rild_cid;

	if (gcd->state == STATE_IDLE)
		return;

	g_ril_print_unsol_no_args(gcd->ril, message);

	g_ril_init_parcel(message, &rilp);

	/* Version */
	parcel_r_int32(&rilp);
	num_calls = parcel_r_int32(&rilp);
	ofono_debug("%s, num_calls = %d", __func__, num_calls);

	if (num_calls <= 0)
		goto data_lost;

	for (i = 0; i < num_calls; i++) {
		parcel_r_int32(&rilp);			/* status */
		parcel_r_int32(&rilp);			/* ignore */
		cid = parcel_r_int32(&rilp);
		active = parcel_r_int32(&rilp);
		parcel_skip_string(&rilp);		/* type */
		parcel_skip_string(&rilp);		/* ifname */
		parcel_skip_string(&rilp);		/* addresses */
		parcel_skip_string(&rilp);		/* dns */
		parcel_skip_string(&rilp);		/* gateways */
		parcel_skip_string(&rilp);		/* pcscf */
		parcel_r_int32(&rilp);			/* mtu */

		ofono_debug("[cid=%d,active=%d]", cid, active);

		/* malformed check */
		if (rilp.malformed) {
			ofono_error("%s: malformed parcel received", __func__);
			return;
		}

		if (cid == used_cid)
			return;
	}

data_lost:
	ofono_debug("%s , cid - %d is lost", __func__, used_cid);
	set_context_disconnected(gcd);
	ofono_gprs_context_deactivated(gc, used_cid);
}

static int gprs_context_set_dns_servers(struct ofono_gprs_context *gc,
					enum ofono_gprs_proto protocol,
					char **dns_addrs)
{
	const char **dns_ipv4_addrs, **dns_ipv6_addrs;
	int proto;
	int ipv4_idx, ipv6_idx;
	int dns_strv_len;
	int i;

	if (protocol == OFONO_GPRS_PROTO_IP) {
		ofono_gprs_context_set_ipv4_dns_servers(gc,
						(const char **) dns_addrs);
		return 0;
	}

	if (protocol == OFONO_GPRS_PROTO_IPV6) {
		ofono_gprs_context_set_ipv6_dns_servers(gc,
						(const char **) dns_addrs);
		return 0;
	}

	dns_strv_len = g_strv_length(dns_addrs);

	dns_ipv4_addrs = g_new0(const char *, dns_strv_len + 1);
	dns_ipv6_addrs = g_new0(const char *, dns_strv_len + 1);

	for (i = 0, ipv4_idx = 0, ipv6_idx = 0; dns_addrs[i]; i++) {
		proto = ril_util_address_to_gprs_proto(dns_addrs[i]);

		if (proto == OFONO_GPRS_PROTO_IP)
			dns_ipv4_addrs[ipv4_idx++] = dns_addrs[i];

		else if (proto == OFONO_GPRS_PROTO_IPV6)
			dns_ipv6_addrs[ipv6_idx++] = dns_addrs[i];
	}

	if (ipv4_idx)
		ofono_gprs_context_set_ipv4_dns_servers(gc, dns_ipv4_addrs);

	if (ipv6_idx)
		ofono_gprs_context_set_ipv6_dns_servers(gc, dns_ipv6_addrs);

	g_free(dns_ipv4_addrs);
	g_free(dns_ipv6_addrs);

	return 0;
}

static int gprs_context_set_gateway(struct ofono_gprs_context *gc,
				enum ofono_gprs_proto protocol,
				char **gateways)
{
	int proto;
	gboolean ipv4_flag, ipv6_flag;
	int i;

	if (protocol == OFONO_GPRS_PROTO_IP) {
		ofono_gprs_context_set_ipv4_gateway(gc, gateways[0]);

		return 0;
	}

	if (protocol == OFONO_GPRS_PROTO_IPV6) {
		ofono_gprs_context_set_ipv6_gateway(gc, gateways[0]);

		return 0;
	}

	ipv4_flag = FALSE;
	ipv6_flag = FALSE;

	for (i = 0; gateways[i]; i++) {
		proto = ril_util_address_to_gprs_proto(gateways[i]);

		if (!ipv4_flag && proto == OFONO_GPRS_PROTO_IP) {
			ofono_gprs_context_set_ipv4_gateway(gc, gateways[i]);

			ipv4_flag = TRUE;
		} else if (!ipv6_flag && proto == OFONO_GPRS_PROTO_IPV6) {
			ofono_gprs_context_set_ipv6_gateway(gc, gateways[i]);

			ipv6_flag = TRUE;
		}

		/*
		 * both IPv4 and IPv6 gateways
		 * have been set, job done
		 */
		if (ipv4_flag && ipv6_flag)
			break;
	}

	return 0;
}

static int gprs_context_set_ipv4_address(struct ofono_gprs_context *gc,
				const char *addr)
{
	char **split_addr = g_strsplit(addr, "/", 2);
	char *netmask;

	/*
	 * Note - the address may optionally include a prefix size
	 * ( Eg. "/30" ).  As this confuses NetworkManager, we
	 * explicitly strip any prefix after calculating the netmask
	 */
	if (split_addr == NULL || g_strv_length(split_addr) == 0) {
		g_strfreev(split_addr);
		return -1;
	}

	netmask = ril_util_get_netmask(addr);

	if (netmask)
		ofono_gprs_context_set_ipv4_netmask(gc, netmask);

	ofono_gprs_context_set_ipv4_address(gc, split_addr[0], TRUE);

	g_strfreev(split_addr);

	return 0;
}

static int gprs_context_set_ipv6_address(struct ofono_gprs_context *gc,
				const char *addr)
{
	char **split_addr = g_strsplit(addr, "/", 2);
	guint64 prefix_ull;
	char *endptr;
	unsigned char prefix;

	if (split_addr == NULL || g_strv_length(split_addr) == 0) {
		g_strfreev(split_addr);
		return -1;
	}

	ofono_gprs_context_set_ipv6_address(gc, split_addr[0]);

	/*
	 * We will set ipv6 prefix length if present
	 * otherwise let connection manager decide
	 */
	if (!split_addr[1]) {
		g_strfreev(split_addr);
		return 0;
	}

	prefix_ull = g_ascii_strtoull(split_addr[1], &endptr, 10);

	/* Discard in case of conversion failure or invalid prefix length */
	if (split_addr[1] == endptr || *endptr != '\0' || prefix_ull > 128) {
		g_strfreev(split_addr);
		return -1;
	}

	prefix = prefix_ull;

	ofono_gprs_context_set_ipv6_prefix_length(gc, prefix);

	g_strfreev(split_addr);

	return 0;
}

static int gprs_context_set_address(struct ofono_gprs_context *gc,
				enum ofono_gprs_proto protocol,
				char **ip_addrs)
{
	int proto;
	gboolean ipv4_flag, ipv6_flag;
	int i;

	if (protocol == OFONO_GPRS_PROTO_IP)
		return gprs_context_set_ipv4_address(gc, ip_addrs[0]);

	if (protocol == OFONO_GPRS_PROTO_IPV6)
		return gprs_context_set_ipv6_address(gc, ip_addrs[0]);

	ipv4_flag = FALSE;
	ipv6_flag = FALSE;

	for (i = 0; ip_addrs[i]; i++) {
		proto = ril_util_address_to_gprs_proto(ip_addrs[i]);

		if (!ipv4_flag && proto == OFONO_GPRS_PROTO_IP) {
			if (gprs_context_set_ipv4_address(gc,
						ip_addrs[i]) != 0)
				return -1;

			ipv4_flag = TRUE;
		} else if (!ipv6_flag &&
			proto == OFONO_GPRS_PROTO_IPV6) {
			if (gprs_context_set_ipv6_address(gc,
						ip_addrs[i]) != 0)
				return -1;

			ipv6_flag = TRUE;
		}

		if (ipv4_flag && ipv6_flag)
			break;
	}

	return 0;
}

static void ril_setup_data_call_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct parcel rilp;
	unsigned int active, cid, num_calls, retry, status, mtu;
	char *type = NULL, *ifname = NULL, *raw_addrs = NULL, *pcscf_addrs = NULL;
	char *raw_dns = NULL, *raw_gws = NULL;
	int protocol;
	struct ofono_gprs_primary_context *ctx =
		ofono_gprs_get_pri_context_by_name(gc, gcd->apn);

	DBG("*gc: %p", gc);

	if (message->error != RIL_E_SUCCESS) {
		ofono_error("%s: setup data call failed for apn: %s - %s",
				__func__, gcd->apn,
				ril_error_to_string(message->error));
		set_context_disconnected(gcd);
		if (ctx != NULL &&
		    ctx->type == OFONO_GPRS_CONTEXT_TYPE_INTERNET) {
			OFONO_DFX_DATA_ACTIVE_FAIL("modem fail");
		}
		goto error;
	}

	g_ril_print_response_no_args(gcd->ril, message);

	g_ril_init_parcel(message, &rilp);

	parcel_r_int32(&rilp);				/* Version */
	num_calls = parcel_r_int32(&rilp);

	if (num_calls != 1) {
		ofono_error("%s: setup_data_call reply for apn: %s,"
				" includes %d calls",
				__func__, gcd->apn, num_calls);
		disconnect_context(gc);
		goto error;
	}

	status = parcel_r_int32(&rilp);
	retry = parcel_r_int32(&rilp);
	ofono_debug("%s - [status=%d,retry=%d]", __func__, status, retry);

	if (status != PDP_FAIL_NONE) {
		if (ctx != NULL &&
		    ctx->type == OFONO_GPRS_CONTEXT_TYPE_INTERNET) {
			char reason_desc[REASON_DESC_SIZE];
			snprintf(reason_desc, REASON_DESC_SIZE, "modem fail:%d",
				 status);
			OFONO_DFX_DATA_ACTIVE_FAIL(reason_desc);
		}

		int delay_s = get_next_activate_retry_delay(gcd, status, retry / 1000);

		if (delay_s > 0) {
			gcd->act_retries += 1;
			gcd->active_retry_cbd = cb_data_new(cb, cbd->data, gc);
			gcd->retry_act_id = g_timeout_add_seconds(
					delay_s, retry_activate, gcd->active_retry_cbd);
			ofono_gprs_set_context_status(gc, CONTEXT_STATUS_RETRYING);

			ofono_debug("%s: retry will happen in %d seconds", __func__, delay_s);
			return;
		} else {
			ofono_error("%s: status for apn: %s, is non-zero: %s",
					__func__, gcd->apn,
					ril_pdp_fail_to_string(status));

			set_context_disconnected(gcd);
			goto error;
		}
	}

	cid = parcel_r_int32(&rilp);
	active = parcel_r_int32(&rilp);
	type = parcel_r_string(&rilp);
	ifname = parcel_r_string(&rilp);
	raw_addrs = parcel_r_string(&rilp);
	raw_dns = parcel_r_string(&rilp);
	raw_gws = parcel_r_string(&rilp);
	pcscf_addrs = parcel_r_string(&rilp);
	mtu = parcel_r_int32(&rilp);

	/* malformed check */
	if (rilp.malformed) {
		ofono_error("%s: malformed parcel received", __func__);
		goto error_free;
	}

	ofono_debug("[status=%d,retry=%d,cid=%d,active=%d,type=%s,ifname=%s,"
		"address=%s,dns=%s,gateways=%s,pcscf_addrs=%s,mtu=%d]",
		status, retry, cid, active, type,
		ifname, raw_addrs, raw_dns, raw_gws, pcscf_addrs, mtu);

	protocol = ril_protocol_string_to_ofono_protocol(type);
	if (protocol < 0) {
		ofono_error("%s: invalid type(protocol) specified: %s",
				__func__, type);
		goto error_free;
	}

	if (ifname == NULL || strlen(ifname) == 0) {
		ofono_error("%s: no interface specified: %s",
				__func__, ifname);
		goto error_free;
	}

	ofono_gprs_context_set_cid(gc, cid);

	ofono_gprs_context_set_interface(gc, ifname);

	/* Split DNS addresses */
	if (raw_dns) {
		char **dns_addrs = g_strsplit(raw_dns, " ", -1);

		/* Check for valid DNS settings, except for MMS contexts */
		if (ofono_gprs_context_get_type(gc) != OFONO_GPRS_CONTEXT_TYPE_MMS &&
		    (dns_addrs == NULL || g_strv_length(dns_addrs) == 0)) {
			g_strfreev(dns_addrs);
			ofono_error("%s: no DNS: %s", __func__, raw_dns);
			goto error_free;
		}

		if (gprs_context_set_dns_servers(gc,
					protocol, dns_addrs) != 0) {
			g_strfreev(dns_addrs);
			goto error_free;
		}

		g_strfreev(dns_addrs);
	}

	/*
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 gateway.
	 */
	if (raw_gws) {
		char **gateways = g_strsplit(raw_gws, " ", -1);

		if (gateways == NULL || g_strv_length(gateways) == 0) {
			g_strfreev(gateways);
			ofono_error("%s: no gateways: %s", __func__, raw_gws);
			goto error_free;
		}

		if (gprs_context_set_gateway(gc, protocol, gateways) != 0) {
			g_strfreev(gateways);
			goto error_free;
		}

		g_strfreev(gateways);
	} else
		goto error_free;

	/* TODO:
	 * RILD can return multiple addresses; oFono only supports
	 * setting a single IPv4 address.  At this time, we only
	 * use the first address.  It's possible that a RIL may
	 * just specify the end-points of the point-to-point
	 * connection, in which case this code will need to
	 * changed to handle such a device.
	 *
	 * For now split into a maximum of three, and only use
	 * the first address for the remaining operations.
	 */
	if (raw_addrs) {
		char **ip_addrs = g_strsplit(raw_addrs, " ", 3);

		if (ip_addrs == NULL || g_strv_length(ip_addrs) == 0) {
			g_strfreev(ip_addrs);
			ofono_error("%s: no ip addrs: %s",
						__func__, raw_addrs);
			goto error_free;
		}

		if (gprs_context_set_address(gc, protocol, ip_addrs) != 0) {
			g_strfreev(ip_addrs);
			goto error_free;
		}

		g_strfreev(ip_addrs);
	}

	/* Parse IMS pcscf addresses */
	if (pcscf_addrs) {
		int ip_type = ril_util_address_to_gprs_proto(pcscf_addrs);

		if (ip_type == OFONO_GPRS_PROTO_IP) {
			ofono_gprs_context_set_ipv4_pcscf(gc, pcscf_addrs);
		} else if (ip_type == OFONO_GPRS_PROTO_IPV6) {
			ofono_gprs_context_set_ipv6_pcscf(gc, pcscf_addrs);
		}
	}

	ofono_gprs_context_set_mtu(gc, mtu);

	g_free(type);
	g_free(ifname);
	g_free(raw_addrs);
	g_free(raw_dns);
	g_free(raw_gws);
	g_free(pcscf_addrs);

	gcd->active_rild_cid = cid;
	gcd->state = STATE_ACTIVE;

	/* activate listener for data call changed events.... */
	gcd->call_list_id =
		g_ril_register(gcd->ril,
				RIL_UNSOL_DATA_CALL_LIST_CHANGED,
				ril_gprs_context_call_list_changed, gc);

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
	return;

error_free:
	g_free(type);
	g_free(ifname);
	g_free(raw_addrs);
	g_free(raw_dns);
	g_free(raw_gws);

	disconnect_context(gc);
error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void ril_gprs_context_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, data, gc);
	struct parcel rilp;

	gcd->act_retries = 0;
	ril_util_build_activate_data_call(gcd->ril, &rilp, ctx->apn, ctx->type,
		ctx->username, ctx->password, ctx->auth_method, ctx->proto, cbd);

	if (g_ril_send(gcd->ril, RIL_REQUEST_SETUP_DATA_CALL, &rilp,
				ril_setup_data_call_cb, cbd, g_free) > 0) {
		gcd->apn = g_strdup(ctx->apn);
		gcd->state = STATE_ENABLING;

		return;
	}
	if (ctx->type == OFONO_GPRS_CONTEXT_TYPE_INTERNET) {
		OFONO_DFX_DATA_ACTIVE_FAIL("ril send fail");
	}
	g_free(cbd);
	CALLBACK_WITH_FAILURE(cb, data);
}

static gboolean reset_modem(gpointer data)
{
	/* TODO call mtk_reset_modem when driver is upstreamed */
	return FALSE;
}

static int get_next_activate_retry_delay(struct gprs_context_data *gcd,
	int fail_cause, int raw_delay)
{
	if (gcd->act_retries >= NUM_ACTIVATION_RETRIES)
		return -1;

	if (fail_cause == PDP_FAIL_VOICE_REGISTRATION_FAIL
			|| fail_cause == PDP_FAIL_DATA_REGISTRATION_FAIL
			|| fail_cause == PDP_FAIL_SIGNAL_LOST
			|| fail_cause == PDP_FAIL_RADIO_POWER_OFF)
		return -1;

	if (raw_delay > 0 && raw_delay < TIME_BETWEEN_ACT_RETRIES_S * NUM_ACTIVATION_RETRIES)
		return raw_delay;

	return TIME_BETWEEN_ACT_RETRIES_S;
}

static gboolean retry_activate(gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_gprs_primary_context *ctx;
	struct parcel rilp;

	if (ofono_gprs_get_context_status(gc) != CONTEXT_STATUS_RETRYING) {
		retry_activate_abort(gc);
		return FALSE;
	}

	ctx = ofono_gprs_get_pri_context_by_name(gc, gcd->apn);
	if (ctx == NULL) {
		ofono_debug("%s - ignore retry due to invalid ctx.", __func__);
		retry_activate_abort(gc);
		return FALSE;
	}

	if (gcd->retry_act_id > 0) {
		g_source_remove(gcd->retry_act_id);
		gcd->retry_act_id = 0;
	}

	ril_util_build_activate_data_call(
		gcd->ril, &rilp, ctx->apn, ctx->type,
			ctx->username, ctx->password, ctx->auth_method, ctx->proto, user_data);

	if (g_ril_send(gcd->ril, RIL_REQUEST_SETUP_DATA_CALL, &rilp,
		       ril_setup_data_call_cb, cbd, g_free) == 0) {
		ofono_error("%s: send ACTIVATE_DATA_CALL failed for apn: %s",
			    __func__, gcd->apn);
		if (ctx->type == OFONO_GPRS_CONTEXT_TYPE_INTERNET) {
			OFONO_DFX_DATA_ACTIVE_FAIL("ril send fail");
		}
		if (cb)
			CALLBACK_WITH_FAILURE(cb, cbd->data);

		g_free(cbd);
	}

	return FALSE;
}

static gboolean retry_deactivate(gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct parcel rilp;

	if (gcd->retry_deact_id > 0) {
		g_source_remove(gcd->retry_deact_id);
		gcd->retry_deact_id = 0;
	}

	/* We might have received a call list update while waiting */
	if (gcd->state == STATE_IDLE) {
		if (cb)
			CALLBACK_WITH_SUCCESS(cb, cbd->data);

		g_free(cbd);

		return FALSE;
	}

	ril_util_build_deactivate_data_call(gcd->ril, &rilp,
					gcd->active_rild_cid,
					RIL_DEACTIVATE_DATA_CALL_NO_REASON);

	if (g_ril_send(gcd->ril, RIL_REQUEST_DEACTIVATE_DATA_CALL, &rilp,
			ril_deactivate_data_call_cb, cbd, g_free) == 0) {
		ofono_error("%s: send DEACTIVATE_DATA_CALL failed for apn: %s",
				__func__, gcd->apn);
		if (cb)
			CALLBACK_WITH_FAILURE(cb, cbd->data);

		g_free(cbd);
	}

	return FALSE;
}

static void ril_deactivate_data_call_cb(struct ril_msg *message,
					gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("*gc: %p", gc);

	if (message->error == RIL_E_SUCCESS) {
		g_ril_print_response_no_args(gcd->ril, message);

		set_context_disconnected(gcd);

		/*
		 * If the deactivate was a result of a data network detach or of
		 * an error in data call establishment, there won't be call
		 * back, so _deactivated() needs to be called directly.
		 */
		if (cb)
			CALLBACK_WITH_SUCCESS(cb, cbd->data);
		else
			ofono_gprs_context_deactivated(gc, gcd->active_rild_cid);

	} else {
		ofono_error("%s: reply failure for apn: %s - %s",
				__func__, gcd->apn,
				ril_error_to_string(message->error));

		/*
		 * It has been detected that some modems fail the deactivation
		 * temporarily. We do retries to handle that case.
		 */
		if (--(gcd->deact_retries) > 0) {
			gcd->deact_retry_cbd = cb_data_new(cb, cbd->data, gc);
			gcd->retry_deact_id =
				g_timeout_add_seconds(
					TIME_BETWEEN_DEACT_RETRIES_S,
					retry_deactivate, gcd->deact_retry_cbd);
		} else {
			ofono_error("%s: retry limit hit", __func__);

			if (cb)
				CALLBACK_WITH_FAILURE(cb, cbd->data);

			/*
			 * Reset modem if MTK. TODO Failures deactivating a
			 * context have not been reported for other modems, but
			 * it would be good to have a generic method to force an
			 * internal reset nonetheless.
			 */
			if (gcd->vendor == OFONO_RIL_VENDOR_MTK)
				gcd->reset_ev_id = g_idle_add(reset_modem, gcd);
		}
	}
}

static void ril_gprs_context_deactivate_primary(struct ofono_gprs_context *gc,
					unsigned int id,
					ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = NULL;
	struct parcel rilp;

	if (gcd->retry_act_id > 0) {
		ofono_info("Abort active retries..., timer_id: %u\n", gcd->retry_act_id);
		retry_activate_abort(gc);

		if (cb) {
			CALLBACK_WITH_SUCCESS(cb, data);
		}

		return;
	}

	ofono_debug("*gc: %p cid: %d active_rild_cid: %d", gc, id,
		gcd->active_rild_cid);

	if (gcd->state == STATE_IDLE || gcd->state == STATE_DISABLING) {
		/* nothing to do */

		if (cb) {
			CALLBACK_WITH_SUCCESS(cb, data);
			g_free(cbd);
		}

		return;
	}

	cbd = cb_data_new(cb, data, gc);

	gcd->state = STATE_DISABLING;
	if (g_ril_unregister(gcd->ril, gcd->call_list_id) == FALSE) {
		ofono_warn("%s: couldn't remove call_list listener"
				" for apn: %s.",
				__func__, gcd->apn);
	}

	gcd->deact_retries = NUM_DEACTIVATION_RETRIES;
	ril_util_build_deactivate_data_call(gcd->ril, &rilp,
					gcd->active_rild_cid,
					RIL_DEACTIVATE_DATA_CALL_NO_REASON);

	if (g_ril_send(gcd->ril, RIL_REQUEST_DEACTIVATE_DATA_CALL, &rilp,
				ril_deactivate_data_call_cb, cbd, g_free) > 0)
		return;

	/* TODO: should we force state to disconnected here? */
	ofono_error("%s: send DEACTIVATE_DATA_CALL failed for apn: %s",
				__func__, gcd->apn);

	if (cb)
			CALLBACK_WITH_FAILURE(cb, data);

	g_free(cbd);
}

static void ril_gprs_context_detach_shutdown(struct ofono_gprs_context *gc,
						unsigned int id)
{
	DBG("*gc: %p cid: %d", gc, id);

	ril_gprs_context_deactivate_primary(gc, 0, NULL, NULL);
}

static int ril_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *data)
{
	GRil *ril = data;
	struct gprs_context_data *gcd;

	DBG("*gc: %p", gc);

	gcd = g_try_new0(struct gprs_context_data, 1);
	if (gcd == NULL)
		return -ENOMEM;

	gcd->ril = g_ril_clone(ril);
	gcd->vendor = vendor;
	set_context_disconnected(gcd);
	gcd->call_list_id = -1;

	ofono_gprs_context_set_data(gc, gcd);

	return 0;
}

static gboolean retry_activate_abort(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	if (gcd->retry_act_id > 0) {
		struct cb_data *cbd = gcd->active_retry_cbd;
		ofono_gprs_context_cb_t cb = cbd->cb;

		g_source_remove(gcd->retry_act_id);
		gcd->retry_act_id = 0;
		set_context_disconnected(gcd);
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(gcd->active_retry_cbd);
		gcd->active_retry_cbd = NULL;

		ofono_gprs_set_context_status(gc, CONTEXT_STATUS_DEACTIVATED);

		return TRUE;
	}

	return FALSE;
}

static void ril_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("*gc: %p", gc);

	if (gcd->state != STATE_IDLE && gcd->state != STATE_DISABLING) {
		struct parcel rilp;

		ril_util_build_deactivate_data_call(gcd->ril, &rilp,
					gcd->active_rild_cid,
					RIL_DEACTIVATE_DATA_CALL_NO_REASON);

		g_ril_send(gcd->ril, RIL_REQUEST_DEACTIVATE_DATA_CALL,
						&rilp, NULL, NULL, NULL);
	}

	if (gcd->retry_deact_id > 0) {
		g_source_remove(gcd->retry_deact_id);
		g_free(gcd->deact_retry_cbd);
	}

	retry_activate_abort(gc);

	if (gcd->reset_ev_id > 0)
		g_source_remove(gcd->reset_ev_id);

	ofono_gprs_context_set_data(gc, NULL);

	g_ril_unref(gcd->ril);
	g_free(gcd);
}

static const struct ofono_gprs_context_driver driver = {
	.name			= RILMODEM,
	.probe			= ril_gprs_context_probe,
	.remove			= ril_gprs_context_remove,
	.activate_primary       = ril_gprs_context_activate_primary,
	.deactivate_primary     = ril_gprs_context_deactivate_primary,
	.detach_shutdown        = ril_gprs_context_detach_shutdown,
};

void ril_gprs_context_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void ril_gprs_context_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
