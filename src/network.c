/*
 *
 *  oFono - Open Source Telephony
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include <kvdb.h>

#include "ofono.h"

#include "common.h"
#include "simutil.h"
#include "util.h"
#include "storage.h"
#include "missing.h"
#include "gril/ril_constants.h"

#define SETTINGS_STORE "netreg"
#define SETTINGS_GROUP "Settings"

#define NETWORK_REGISTRATION_FLAG_HOME_SHOW_PLMN	0x1
#define NETWORK_REGISTRATION_FLAG_ROAMING_SHOW_SPN	0x2
#define NETWORK_REGISTRATION_FLAG_READING_PNN		0x4

enum network_registration_mode {
	NETWORK_REGISTRATION_MODE_AUTO =	0,
	NETWORK_REGISTRATION_MODE_MANUAL =	2,
	NETWORK_REGISTRATION_MODE_AUTO_ONLY =	5, /* Out of range of 27.007 */
};

struct ofono_netreg {
	int status;
	int location;
	int cellid;
	int technology;
	int denial_reason;
	int mode;
	char *base_station;
	char *nitz_time;
	struct network_operator_data *current_operator;
	GSList *operator_list;
	struct ofono_network_registration_ops *ops;
	int flags;
	DBusMessage *pending;
	int signal_strength;
	struct ofono_signal_strength *signal_strength_data;
	ofono_bool_t signal_strength_changed;
	struct sim_spdi *spdi;
	struct sim_eons *eons;
	struct ofono_sim *sim;
	struct ofono_sim_context *sim_context;
	unsigned int sim_watch;
	unsigned int sim_state_watch;
	unsigned int sim_efpnn_watch;
	unsigned int sim_efopl_watch;
	unsigned int sim_efcphs_csp_watch;
	GKeyFile *settings;
	char *imsi;
	struct ofono_watchlist *status_watches;
	const struct ofono_netreg_driver *driver;
	void *driver_data;
	struct ofono_atom *atom;
	unsigned int hfp_watch;
	unsigned int spn_watch;
	unsigned int radio_online_watch;
	struct timespec oos_start_time;
	int oos_duration;
	int report_oos_time_id;
	ofono_bool_t oos_by_radio_on_flag;
	int signal_level_duration[6]; // 6 diff level base enum ofono_signal_strength_level
	struct timespec signal_level_start_time;
	int current_signal_level;
	int signal_level_time_id;
	int rat_duration[4]; // just consider 1-2g,2-3g,3-4g,0-other rat
	struct timespec rat_start_time;
	int current_rat;
	int  rat_report_time_id;
	int radio_status;
};

struct network_operator_data {
	char name[OFONO_MAX_OPERATOR_NAME_LENGTH + 1];
	char mcc[OFONO_MAX_MCC_LENGTH + 1];
	char mnc[OFONO_MAX_MNC_LENGTH + 1];
	int status;
	unsigned int techs;
	const struct sim_eons_operator_info *eons_info;
	struct ofono_netreg *netreg;
};

static GSList *g_drivers = NULL;

static const char *registration_mode_to_string(int mode)
{
	switch (mode) {
	case NETWORK_REGISTRATION_MODE_AUTO:
		return "auto";
	case NETWORK_REGISTRATION_MODE_AUTO_ONLY:
		return "auto-only";
	case NETWORK_REGISTRATION_MODE_MANUAL:
		return "manual";
	}

	return "unknown";
}

static inline const char *network_operator_status_to_string(int status)
{
	switch (status) {
	case OPERATOR_STATUS_AVAILABLE:
		return "available";
	case OPERATOR_STATUS_CURRENT:
		return "current";
	case OPERATOR_STATUS_FORBIDDEN:
		return "forbidden";
	}

	return "unknown";
}

static char **network_operator_technologies(struct network_operator_data *opd)
{
	unsigned int ntechs = 0;
	char **techs;
	unsigned int i;

	for (i = 0; i < sizeof(opd->techs) * 8; i++) {
		if (opd->techs & (1u << i))
			ntechs += 1;
	}

	techs = g_new0(char *, ntechs + 1);
	ntechs = 0;

	for (i = 0; i < sizeof(opd->techs) * 8; i++) {
		if (!(opd->techs & (1u << i)))
			continue;

		techs[ntechs++] = g_strdup(registration_tech_to_string(i));
	}

	return techs;
}

static void registration_status_callback(const struct ofono_error *error,
					int status, int lac, int ci, int tech, int denial,
					void *data)
{
	struct ofono_netreg *netreg = data;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		ofono_error("Error during registration status query");
		return;
	}

	ofono_netreg_status_notify(netreg, status, lac, ci, tech, denial);
}

static void init_register(const struct ofono_error *error, void *data)
{
	struct ofono_netreg *netreg = data;

	if (netreg->driver->registration_status == NULL)
		return;

	netreg->driver->registration_status(netreg,
					registration_status_callback, netreg);
}

static void enforce_auto_only(struct ofono_netreg *netreg)
{
	if (netreg->mode != NETWORK_REGISTRATION_MODE_MANUAL)
		return;

	if (netreg->driver->register_auto == NULL)
		return;

	netreg->driver->register_auto(netreg, init_register, netreg);
}

static void set_registration_mode(struct ofono_netreg *netreg, int mode)
{
	DBusConnection *conn;
	const char *strmode;
	const char *path;

	if (netreg->mode == mode)
		return;

	if (mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
		enforce_auto_only(netreg);

	netreg->mode = mode;

	if (netreg->settings) {
		const char *mode_str;

		if (netreg->mode == NETWORK_REGISTRATION_MODE_MANUAL)
			mode_str = "manual";
		else
			mode_str = "auto";

		g_key_file_set_string(netreg->settings, SETTINGS_GROUP,
					"Mode", mode_str);
		storage_sync(netreg->imsi, SETTINGS_STORE, netreg->settings);
	}

	strmode = registration_mode_to_string(mode);

	conn = ofono_dbus_get_connection();
	path = __ofono_atom_get_path(netreg->atom);

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"Mode", DBUS_TYPE_STRING, &strmode);
}

static void register_callback(const struct ofono_error *error, void *data)
{
	struct ofono_netreg *netreg = data;
	DBusMessage *reply;

	if (error->type == OFONO_ERROR_TYPE_NO_ERROR)
		reply = dbus_message_new_method_return(netreg->pending);
	else
		reply = __ofono_error_from_error(error, netreg->pending);

	__ofono_dbus_pending_reply(&netreg->pending, reply);

	if (netreg->driver->registration_status == NULL)
		return;

	netreg->driver->registration_status(netreg,
						registration_status_callback,
						netreg);
}

static struct network_operator_data *
	network_operator_create(const struct ofono_network_operator *op)
{
	struct network_operator_data *opd;

	opd = g_new0(struct network_operator_data, 1);

	memcpy(&opd->name, op->name, sizeof(opd->name));
	memcpy(&opd->mcc, op->mcc, sizeof(opd->mcc));
	memcpy(&opd->mnc, op->mnc, sizeof(opd->mnc));

	opd->status = op->status;

	if (op->tech != -1)
		opd->techs |= 1 << op->tech;

	return opd;
}

static void network_operator_destroy(gpointer user_data)
{
	struct network_operator_data *op = user_data;

	g_free(op);
}

static gint network_operator_compare(gconstpointer a, gconstpointer b)
{
	const struct network_operator_data *opda = a;
	const struct ofono_network_operator *opb = b;

	int comp1;
	int comp2;

	comp1 = strcmp(opda->mcc, opb->mcc);
	comp2 = strcmp(opda->mnc, opb->mnc);

	return comp1 != 0 ? comp1 : comp2;
}

static gint network_operator_data_compare(gconstpointer a, gconstpointer b)
{
	const struct network_operator_data *opa = a;
	const struct network_operator_data *opb = b;

	int comp1;
	int comp2;

	comp1 = strcmp(opa->mcc, opb->mcc);
	comp2 = strcmp(opa->mnc, opb->mnc);

	return comp1 != 0 ? comp1 : comp2;
}

static const char *network_operator_build_path(struct ofono_netreg *netreg,
							const char *mcc,
							const char *mnc)
{
	static char path[256];

	snprintf(path, sizeof(path), "%s/operator/%s%s",
			__ofono_atom_get_path(netreg->atom),
			mcc, mnc);

	return path;
}

static void set_network_operator_status(struct network_operator_data *opd,
					int status)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_netreg *netreg = opd->netreg;
	const char *status_str;
	const char *path;

	if (opd->status == status)
		return;

	opd->status = status;

	/* Don't emit for the case where only operator name is reported */
	if (opd->mcc[0] == '\0' && opd->mnc[0] == '\0')
		return;

	status_str = network_operator_status_to_string(status);
	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_OPERATOR_INTERFACE,
					"Status", DBUS_TYPE_STRING,
					&status_str);
}

static void set_network_operator_techs(struct network_operator_data *opd,
					unsigned int techs)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_netreg *netreg = opd->netreg;
	char **technologies;
	const char *path;

	if (opd->techs == techs)
		return;

	opd->techs = techs;
	technologies = network_operator_technologies(opd);
	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);

	ofono_dbus_signal_array_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"Technologies", DBUS_TYPE_STRING,
					&technologies);
	g_strfreev(technologies);
}

static char *get_operator_display_name(struct ofono_netreg *netreg)
{
	struct network_operator_data *opd = netreg->current_operator;
	const char *plmn;
	const char *spn;
	static char name[1024];
	static char mccmnc[OFONO_MAX_MCC_LENGTH + OFONO_MAX_MNC_LENGTH + 1];
	int len = sizeof(name);
	int home_or_spdi;

	/*
	 * The name displayed to user depends on whether we're in a home
	 * PLMN or roaming and on configuration bits from the SIM, all
	 * together there are four cases to consider.
	 */

	if (opd == NULL) {
		g_strlcpy(name, "", len);
		return name;
	}

	plmn = opd->name;

	/*
	 * This is a fallback on some really broken hardware which do not
	 * report the COPS name
	 */
	if (plmn[0] == '\0') {
		snprintf(mccmnc, sizeof(mccmnc), "%s%s", opd->mcc, opd->mnc);
		plmn = mccmnc;
	}

	if (opd->eons_info && opd->eons_info->longname)
		plmn = opd->eons_info->longname;

	spn = ofono_sim_get_spn(netreg->sim);

	if (spn == NULL || strlen(spn) == 0) {
		g_strlcpy(name, plmn, len);
		return name;
	}

	if (netreg->status == NETWORK_REGISTRATION_STATUS_REGISTERED)
		home_or_spdi = TRUE;
	else
		home_or_spdi = sim_spdi_lookup(netreg->spdi,
							opd->mcc, opd->mnc);

	if (home_or_spdi)
		if (netreg->flags & NETWORK_REGISTRATION_FLAG_HOME_SHOW_PLMN)
			/* Case 1 */
			snprintf(name, len, "%s (%s)", spn, plmn);
		else
			/* Case 2 */
			snprintf(name, len, "%s", spn);
	else
		if (netreg->flags & NETWORK_REGISTRATION_FLAG_ROAMING_SHOW_SPN)
			/* Case 3 */
			snprintf(name, len, "%s (%s)", spn, plmn);
		else
			/* Case 4 */
			snprintf(name, len, "%s", plmn);

	return name;
}

static void netreg_emit_operator_display_name(struct ofono_netreg *netreg)
{
	const char *operator = get_operator_display_name(netreg);

	ofono_dbus_signal_property_changed(ofono_dbus_get_connection(),
					__ofono_atom_get_path(netreg->atom),
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"Name", DBUS_TYPE_STRING, &operator);
}

static void set_network_operator_name(struct network_operator_data *opd,
					const char *name)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_netreg *netreg = opd->netreg;
	const char *path;

	if (name[0] == '\0')
		return;

	if (!strncmp(opd->name, name, OFONO_MAX_OPERATOR_NAME_LENGTH))
		return;

	strncpy(opd->name, name, OFONO_MAX_OPERATOR_NAME_LENGTH);
	opd->name[OFONO_MAX_OPERATOR_NAME_LENGTH] = '\0';

	/*
	 * If we have Enhanced Operator Name info on the SIM, we always use
	 * that, so do not need to emit the signal here
	 */
	if (opd->eons_info && opd->eons_info->longname)
		return;

	if (opd == netreg->current_operator)
		netreg_emit_operator_display_name(netreg);

	/* Don't emit when only operator name is reported */
	if (opd->mcc[0] == '\0' && opd->mnc[0] == '\0')
		return;

	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_OPERATOR_INTERFACE,
					"Name", DBUS_TYPE_STRING, &name);
}

static void set_network_operator_eons_info(struct network_operator_data *opd,
				const struct sim_eons_operator_info *eons_info)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_netreg *netreg = opd->netreg;
	const struct sim_eons_operator_info *old_eons_info = opd->eons_info;
	const char *path;
	const char *oldname;
	const char *newname;
	const char *oldinfo;
	const char *newinfo;

	if (old_eons_info == NULL && eons_info == NULL)
		return;

	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);
	opd->eons_info = eons_info;

	if (old_eons_info && old_eons_info->longname)
		oldname = old_eons_info->longname;
	else
		oldname = opd->name;

	if (eons_info && eons_info->longname)
		newname = eons_info->longname;
	else
		newname = opd->name;

	if (oldname != newname && strcmp(oldname, newname)) {
		ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_OPERATOR_INTERFACE,
					"Name", DBUS_TYPE_STRING, &newname);

		if (opd == netreg->current_operator)
			netreg_emit_operator_display_name(netreg);
	}

	if (old_eons_info && old_eons_info->info)
		oldinfo = old_eons_info->info;
	else
		oldinfo = "";

	if (eons_info && eons_info->info)
		newinfo = eons_info->info;
	else
		newinfo = "";

	if (oldinfo != newinfo && strcmp(oldinfo, newinfo))
		ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_OPERATOR_INTERFACE,
					"AdditionalInformation",
					DBUS_TYPE_STRING, &newinfo);
}

static void append_operator_properties(struct network_operator_data *opd,
					DBusMessageIter *dict)
{
	const char *name = opd->name;
	const char *status = network_operator_status_to_string(opd->status);
	char mccmnc[OFONO_MAX_MCC_LENGTH + OFONO_MAX_MNC_LENGTH + 1];

	if (opd->eons_info && opd->eons_info->longname)
		name = opd->eons_info->longname;

	if (name[0] == '\0') {
		snprintf(mccmnc, sizeof(mccmnc), "%s%s", opd->mcc, opd->mnc);
		name = mccmnc;
	}

	ofono_dbus_dict_append(dict, "Name", DBUS_TYPE_STRING, &name);

	ofono_dbus_dict_append(dict, "Status", DBUS_TYPE_STRING, &status);

	if (*opd->mcc != '\0') {
		const char *mcc = opd->mcc;
		ofono_dbus_dict_append(dict, "MobileCountryCode",
					DBUS_TYPE_STRING, &mcc);
	}

	if (*opd->mnc != '\0') {
		const char *mnc = opd->mnc;
		ofono_dbus_dict_append(dict, "MobileNetworkCode",
					DBUS_TYPE_STRING, &mnc);
	}

	if (opd->techs != 0) {
		char **technologies = network_operator_technologies(opd);

		ofono_dbus_dict_append_array(dict, "Technologies",
						DBUS_TYPE_STRING,
						&technologies);

		g_strfreev(technologies);
	}

	if (opd->eons_info && opd->eons_info->info) {
		const char *additional = opd->eons_info->info;

		ofono_dbus_dict_append(dict, "AdditionalInformation",
					DBUS_TYPE_STRING, &additional);
	}
}

static DBusMessage *network_operator_get_properties(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct network_operator_data *opd = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);

	append_operator_properties(opd, &dict);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *network_operator_register(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_operator_data *opd = data;
	struct ofono_netreg *netreg = opd->netreg;

	if (netreg->mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
		return __ofono_error_access_denied(msg);

	if (netreg->pending)
		return __ofono_error_busy(msg);

	if (netreg->driver->register_manual == NULL)
		return __ofono_error_not_implemented(msg);

	netreg->pending = dbus_message_ref(msg);

	netreg->driver->register_manual(netreg, opd->mcc, opd->mnc,
					registration_tech_to_string(opd->techs),
					register_callback, netreg);

	set_registration_mode(netreg, NETWORK_REGISTRATION_MODE_MANUAL);

	return NULL;
}

static const GDBusMethodTable network_operator_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			network_operator_get_properties) },
	{ GDBUS_ASYNC_METHOD("Register", NULL, NULL,
						network_operator_register) },
	{ }
};

static const GDBusSignalTable network_operator_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

static gboolean network_operator_dbus_register(struct ofono_netreg *netreg,
					struct network_operator_data *opd)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;

	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);

	if (!g_dbus_register_interface(conn, path,
					OFONO_NETWORK_OPERATOR_INTERFACE,
					network_operator_methods,
					network_operator_signals,
					NULL, opd,
					network_operator_destroy)) {
		ofono_error("Could not register NetworkOperator %s", path);
		return FALSE;
	}

	opd->netreg = netreg;
	opd->eons_info = NULL;

	if (netreg->eons)
		opd->eons_info = sim_eons_lookup(netreg->eons,
							opd->mcc, opd->mnc);

	return TRUE;
}

static gboolean network_operator_dbus_unregister(struct ofono_netreg *netreg,
					struct network_operator_data *opd)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;

	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);

	return g_dbus_unregister_interface(conn, path,
					OFONO_NETWORK_OPERATOR_INTERFACE);
}

static GSList *compress_operator_list(const struct ofono_network_operator *list,
					int total)
{
	GSList *oplist = 0;
	GSList *o;
	int i;
	struct network_operator_data *opd;

	for (i = 0; i < total; i++) {
		o = NULL;

		if (list[i].mcc[0] == '\0' || list[i].mnc[0] == '\0')
			continue;

		if (oplist)
			o = g_slist_find_custom(oplist, &list[i],
						network_operator_compare);

		if (o == NULL) {
			opd = network_operator_create(&list[i]);
			oplist = g_slist_prepend(oplist, opd);
		} else if (o && list[i].tech != -1) {
			opd = o->data;
			opd->techs |= 1 << list[i].tech;
		}
	}

	if (oplist)
		oplist = g_slist_reverse(oplist);

	return oplist;
}

static gboolean update_operator_list(struct ofono_netreg *netreg, int total,
				const struct ofono_network_operator *list)
{
	GSList *n = NULL;
	GSList *o;
	GSList *compressed;
	GSList *c;
	struct network_operator_data *current_op = NULL;
	gboolean changed = FALSE;

	compressed = compress_operator_list(list, total);

	for (c = compressed; c; c = c->next) {
		struct network_operator_data *copd = c->data;

		o = g_slist_find_custom(netreg->operator_list, copd,
					network_operator_data_compare);

		if (o) { /* Update and move to a new list */
			set_network_operator_status(o->data, copd->status);
			set_network_operator_techs(o->data, copd->techs);
			set_network_operator_name(o->data, copd->name);

			n = g_slist_prepend(n, o->data);
			netreg->operator_list =
				g_slist_remove(netreg->operator_list, o->data);
		} else {
			/* New operator */
			struct network_operator_data *opd;

			opd = g_memdup2(copd,
					sizeof(struct network_operator_data));

			if (!network_operator_dbus_register(netreg, opd)) {
				g_free(opd);
				continue;
			}

			n = g_slist_prepend(n, opd);
			changed = TRUE;
		}
	}

	g_slist_free_full(compressed, g_free);

	if (n)
		n = g_slist_reverse(n);

	if (netreg->operator_list)
		changed = TRUE;

	for (o = netreg->operator_list; o; o = o->next) {
		struct network_operator_data *op = o->data;
		if (op != op->netreg->current_operator)
			network_operator_dbus_unregister(netreg, op);
		else
			current_op = op;
	}

	if (current_op) {
		n = g_slist_prepend(n, current_op);
		netreg->operator_list =
			g_slist_remove(netreg->operator_list, current_op);
	}

	g_slist_free(netreg->operator_list);

	netreg->operator_list = n;

	return changed;
}

static void gw_signal_strength_dict_append(DBusMessageIter *dict,
	const struct ofono_gw_signal_strength *gw_signal_strength)
{
	ofono_dbus_dict_append(dict, "ReceivedSignalStrengthIndicator",
				DBUS_TYPE_INT32, &gw_signal_strength->rssi);
}

static void lte_signal_strength_dict_append(DBusMessageIter *dict,
	const struct ofono_lte_signal_strength *lte_signal_strength)
{
	ofono_dbus_dict_append(dict, "ReceivedSignalStrengthIndicator",
				DBUS_TYPE_INT32, &lte_signal_strength->rssi);

	ofono_dbus_dict_append(dict, "ReferenceSignalReceivedPower",
				DBUS_TYPE_INT32, &lte_signal_strength->rsrp);

	ofono_dbus_dict_append(dict, "ReferenceSignalReceivedQuality",
				DBUS_TYPE_INT32, &lte_signal_strength->rsrq);

	ofono_dbus_dict_append(dict, "SingalToNoiseRatio",
				DBUS_TYPE_INT32, &lte_signal_strength->rssnr);

	ofono_dbus_dict_append(dict, "ChannelQualityIndicator",
				DBUS_TYPE_INT32, &lte_signal_strength->cqi);
}

static void fill_signal_strength_data(struct ofono_netreg *netreg, DBusMessageIter *iter)
{
	DBusMessageIter variant;
	DBusMessageIter array;
	char typesig[5];
	char arraysig[6];

	arraysig[0] = DBUS_TYPE_ARRAY;
	arraysig[1] = typesig[0] = DBUS_DICT_ENTRY_BEGIN_CHAR;
	arraysig[2] = typesig[1] = DBUS_TYPE_STRING;
	arraysig[3] = typesig[2] = DBUS_TYPE_VARIANT;
	arraysig[4] = typesig[3] = DBUS_DICT_ENTRY_END_CHAR;
	arraysig[5] = typesig[4] = '\0';

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						arraysig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						typesig, &array);

	if (netreg->signal_strength_data) {
		if (netreg->technology == RADIO_TECH_UMTS
			&& netreg->signal_strength_data->gw_signal_strength) {
			gw_signal_strength_dict_append(&array,
				netreg->signal_strength_data->gw_signal_strength);
		}

		if (netreg->technology == RADIO_TECH_LTE
			&& netreg->signal_strength_data->lte_signal_strength) {
			lte_signal_strength_dict_append(&array,
				netreg->signal_strength_data->lte_signal_strength);
		}

		ofono_dbus_dict_append(&array, "Level",
				DBUS_TYPE_INT32, &netreg->signal_strength_data->level);
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

static void append_signal_strength_dict(struct ofono_netreg *netreg, DBusMessageIter *dict)
{
	DBusMessageIter entry;
	const char *key = "SignalStrength";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	fill_signal_strength_data(netreg, &entry);

	dbus_message_iter_close_container(dict, &entry);
}

static void netreg_emit_signal_strength_changed(struct ofono_netreg *netreg)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);
	DBusMessage *signal;
	DBusMessageIter iter;
	const char *key = "SignalStrength";

	signal = dbus_message_new_signal(path, OFONO_NETWORK_REGISTRATION_INTERFACE,
						"PropertyChanged");

	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key);
	fill_signal_strength_data(netreg, &iter);

	netreg->signal_strength_changed = FALSE;
	g_dbus_send_message(conn, signal);
}

static DBusMessage *network_get_properties(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct ofono_netreg *netreg = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;

	const char *status = registration_status_to_string(netreg->status);
	const char *operator;
	const char *mode = registration_mode_to_string(netreg->mode);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);

	ofono_dbus_dict_append(&dict, "Status", DBUS_TYPE_STRING, &status);
	ofono_dbus_dict_append(&dict, "Mode", DBUS_TYPE_STRING, &mode);

	if (netreg->location != -1) {
		dbus_uint16_t location = netreg->location;
		ofono_dbus_dict_append(&dict, "LocationAreaCode",
					DBUS_TYPE_UINT16, &location);
	}

	if (netreg->cellid != -1) {
		dbus_uint32_t cellid = netreg->cellid;
		ofono_dbus_dict_append(&dict, "CellId",
					DBUS_TYPE_UINT32, &cellid);
	}

	if (netreg->technology != -1) {
		ofono_dbus_dict_append(&dict, "Technology", DBUS_TYPE_INT32,
					&netreg->technology);
	}

	if (netreg->denial_reason != -1) {
		ofono_dbus_dict_append(&dict, "DenialReason", DBUS_TYPE_UINT16,
					&netreg->denial_reason);
	}

	if (netreg->current_operator) {
		if (netreg->current_operator->mcc[0] != '\0') {
			const char *mcc = netreg->current_operator->mcc;
			ofono_dbus_dict_append(&dict, "MobileCountryCode",
						DBUS_TYPE_STRING, &mcc);
		}

		if (netreg->current_operator->mnc[0] != '\0') {
			const char *mnc = netreg->current_operator->mnc;
			ofono_dbus_dict_append(&dict, "MobileNetworkCode",
						DBUS_TYPE_STRING, &mnc);
		}
	}

	operator = get_operator_display_name(netreg);
	ofono_dbus_dict_append(&dict, "Name", DBUS_TYPE_STRING, &operator);

	if (netreg->signal_strength != -1) {
		unsigned char strength = netreg->signal_strength;

		ofono_dbus_dict_append(&dict, "Strength", DBUS_TYPE_BYTE,
					&strength);
	}

	if (netreg->nitz_time) {
		ofono_dbus_dict_append(&dict, "NITZ", DBUS_TYPE_STRING,
					&netreg->nitz_time);
	}

	if (netreg->base_station)
		ofono_dbus_dict_append(&dict, "BaseStation", DBUS_TYPE_STRING,
					&netreg->base_station);

	if (netreg->signal_strength_data)
		append_signal_strength_dict(netreg, &dict);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *network_register(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct ofono_netreg *netreg = data;

	if (netreg->mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
		return __ofono_error_access_denied(msg);

	if (netreg->pending)
		return __ofono_error_busy(msg);

	if (netreg->driver->register_auto == NULL)
		return __ofono_error_not_implemented(msg);

	netreg->pending = dbus_message_ref(msg);

	netreg->driver->register_auto(netreg, register_callback, netreg);

	set_registration_mode(netreg, NETWORK_REGISTRATION_MODE_AUTO);

	return NULL;
}

static void append_operator_struct(struct ofono_netreg *netreg,
					struct network_operator_data *opd,
					DBusMessageIter *iter)
{
	DBusMessageIter entry, dict;
	const char *path;

	path = network_operator_build_path(netreg, opd->mcc, opd->mnc);

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);
	append_operator_properties(opd, &dict);
	dbus_message_iter_close_container(&entry, &dict);
	dbus_message_iter_close_container(iter, &entry);
}

static void append_operator_struct_list(struct ofono_netreg *netreg,
					DBusMessageIter *array)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	char **children;
	char path[256];
	GSList *l;

	snprintf(path, sizeof(path), "%s/operator",
			__ofono_atom_get_path(netreg->atom));

	if (!dbus_connection_list_registered(conn, path, &children)) {
		ofono_warn("Unable to obtain registered NetworkOperator(s)");
		return;
	}

	/*
	 * Quoting 27.007: "The list of operators shall be in order: home
	 * network, networks referenced in SIM or active application in the
	 * UICC (GSM or USIM) in the following order: HPLMN selector, User
	 * controlled PLMN selector, Operator controlled PLMN selector and
	 * PLMN selector (in the SIM or GSM application), and other networks."
	 * Thus we must make sure we return the list in the same order,
	 * if possible.  Luckily the operator_list is stored in order already
	 */
	for (l = netreg->operator_list; l; l = l->next) {
		struct network_operator_data *opd = l->data;
		char mnc[OFONO_MAX_MNC_LENGTH + 1];
		char mcc[OFONO_MAX_MCC_LENGTH + 1];
		int j;

		for (j = 0; children[j]; j++) {
			sscanf(children[j], "%3[0-9]%[0-9]", mcc, mnc);

			if (!strcmp(opd->mcc, mcc) && !strcmp(opd->mnc, mnc))
				append_operator_struct(netreg, opd, array);
		}
	}

	dbus_free_string_array(children);
}

static void operator_list_callback(const struct ofono_error *error, int total,
				const struct ofono_network_operator *list,
				void *data)
{
	struct ofono_netreg *netreg = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		ofono_error("Error occurred during operator list");
		__ofono_dbus_pending_reply(&netreg->pending,
					__ofono_error_failed(netreg->pending));
		return;
	}

	update_operator_list(netreg, total, list);

	reply = dbus_message_new_method_return(netreg->pending);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_OBJECT_PATH_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_STRUCT_END_CHAR_AS_STRING,
					&array);
	append_operator_struct_list(netreg, &array);
	dbus_message_iter_close_container(&iter, &array);

	__ofono_dbus_pending_reply(&netreg->pending, reply);
}

static DBusMessage *network_scan(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct ofono_netreg *netreg = data;

	if (netreg->mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
		return __ofono_error_access_denied(msg);

	if (netreg->pending)
		return __ofono_error_busy(msg);

	if (netreg->driver->list_operators == NULL)
		return __ofono_error_not_implemented(msg);

	netreg->pending = dbus_message_ref(msg);

	netreg->driver->list_operators(netreg, operator_list_callback, netreg);

	return NULL;
}

static DBusMessage *network_register_manual(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct ofono_netreg *netreg = data;
	const char *mcc, *mnc, *tech;

	if (netreg->mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
		return __ofono_error_access_denied(msg);

	if (netreg->pending)
		return __ofono_error_busy(msg);

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &mcc,
					DBUS_TYPE_STRING, &mnc,
					DBUS_TYPE_STRING, &tech,
					DBUS_TYPE_INVALID) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (netreg->driver->register_manual == NULL)
		return __ofono_error_not_implemented(msg);

	netreg->pending = dbus_message_ref(msg);

	netreg->driver->register_manual(netreg, mcc, mnc, tech,
					register_callback, netreg);

	set_registration_mode(netreg, NETWORK_REGISTRATION_MODE_MANUAL);

	return NULL;
}

static DBusMessage *network_get_operators(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct ofono_netreg *netreg = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_OBJECT_PATH_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_STRUCT_END_CHAR_AS_STRING,
					&array);
	append_operator_struct_list(netreg, &array);
	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static const GDBusMethodTable network_registration_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			network_get_properties) },
	{ GDBUS_ASYNC_METHOD("Register",
				NULL, NULL, network_register) },
	{ GDBUS_ASYNC_METHOD("RegisterManual",
		GDBUS_ARGS({ "mcc", "s"}, { "mnc", "s"}, { "tech", "s"}), NULL,
		network_register_manual) },
	{ GDBUS_METHOD("GetOperators",
		NULL, GDBUS_ARGS({ "operators_with_properties", "a(oa{sv})" }),
		network_get_operators) },
	{ GDBUS_ASYNC_METHOD("Scan",
		NULL, GDBUS_ARGS({ "operators_with_properties", "a(oa{sv})" }),
		network_scan) },
	{ }
};

static const GDBusSignalTable network_registration_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

static void set_registration_status(struct ofono_netreg *netreg, int status)
{
	const char *str_status = registration_status_to_string(status);
	const char *path = __ofono_atom_get_path(netreg->atom);
	DBusConnection *conn = ofono_dbus_get_connection();

	if (netreg->status == status)
		return;

	netreg->status = status;

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"Status", DBUS_TYPE_STRING,
					&str_status);
}

static void set_registration_location(struct ofono_netreg *netreg, int lac)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);
	dbus_uint16_t dbus_lac = lac;

	if (lac > 0xffff || netreg->location == lac)
		return;

	netreg->location = lac;

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"LocationAreaCode",
					DBUS_TYPE_UINT16, &dbus_lac);
}

static void set_registration_cellid(struct ofono_netreg *netreg, int ci)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);
	dbus_uint32_t dbus_ci = ci;

	if (netreg->cellid == ci)
		return;

	netreg->cellid = ci;

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"CellId", DBUS_TYPE_UINT32, &dbus_ci);
}

static void set_registration_denial_reason(struct ofono_netreg *netreg, int denial)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);
	dbus_uint16_t dbus_denial_reason = denial;

	if (denial > 0xffff || denial == -1)
		return;

	netreg->denial_reason = denial;

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"DenialReason",
					DBUS_TYPE_UINT16, &dbus_denial_reason);
}

void update_rat_duration(struct ofono_netreg *netreg, int rat_value)
{
	struct timespec update_time;

	clock_gettime(CLOCK_MONOTONIC, &update_time);
	ofono_debug("update_rat_duration:%d,%d,%d",
		    netreg->rat_start_time.tv_sec != 0 ||
			    netreg->rat_start_time.tv_nsec != 0,
		    netreg->status, netreg->radio_status);

	if (netreg->rat_start_time.tv_sec != 0 ||
	    netreg->rat_start_time.tv_nsec != 0) {
		int temp_value =
			update_time.tv_sec - netreg->rat_start_time.tv_sec;
		netreg->rat_duration[netreg->current_rat] =
			temp_value + netreg->rat_duration[netreg->current_rat];
	}
	if ((netreg->status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
	     netreg->status == NETWORK_REGISTRATION_STATUS_ROAMING) &&
	    netreg->radio_status == RADIO_STATUS_ON) {
		netreg->rat_start_time = update_time;
		netreg->current_rat = rat_value;
	} else {
		memset(&netreg->rat_start_time, 0,
		       sizeof(netreg->rat_start_time));
	}
}

static void set_rat_value_to_env(int tech, struct ofono_netreg *netreg)
{
	char *rat_type = NULL;
	size_t rat_type_length = 0;
	int rat_value = OFONO_OTHER;

	switch (tech) {
		case RADIO_TECH_GPRS:
		case RADIO_TECH_EDGE:
		case RADIO_TECH_GSM:
			rat_type = "2g";
			rat_value = OFONO_2G;
			break;
		case RADIO_TECH_UMTS:
		case RADIO_TECH_HSDPA:
		case RADIO_TECH_HSUPA:
		case RADIO_TECH_HSPA:
			rat_type = "3g";
			rat_value = OFONO_3G;
			break;
		case RADIO_TECH_LTE:
		case RADIO_TECH_LTE_CA:
			rat_type = "4g";
			rat_value = OFONO_4G;
			break;
		case RADIO_TECH_NR:
			rat_type = "5g";
			rat_value = OFONO_OTHER;
			break;
		case RADIO_TECH_UNKNOWN:
			rat_type = "none";
			rat_value = OFONO_OTHER;
			break;
		default:
			rat_type = "others";
			rat_value = OFONO_OTHER;
			break;
	}

	rat_type_length = strlen(rat_type);
	if (property_set_buffer("TELEPHONY_TYPE", rat_type, rat_type_length) != 0) {
		ofono_error("Failed to set TELEPHONY_TYPE property");
	}
	update_rat_duration(netreg, rat_value);
}

static void set_registration_technology(struct ofono_netreg *netreg, int tech)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);

	set_rat_value_to_env(tech, netreg);

	if (netreg->technology == tech)
		return;

	netreg->technology = tech;

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"Technology", DBUS_TYPE_INT32,
					&netreg->technology);
}

static void set_nitz_time(struct ofono_netreg *netreg,
					struct ofono_network_time *info)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);
	char buf[128];
	const char *nitz_str = buf;
	int error_code;

	if (netreg->nitz_time == NULL && info == NULL)
		return;

	if (netreg->nitz_time)
		g_free(netreg->nitz_time);

	if (info) {
		error_code = snprintf(buf, sizeof(buf), "%d,%d,%d,%d,%d,%d,%d,%d",
			info->sec, info->min, info->hour,
			info->mday, info->mon, info->year,
			info->dst, info->utcoff);
		if (error_code < 0) {
			ofono_error("Error during set nitz time");
			netreg->nitz_time = NULL;
			return;
		} else {
			netreg->nitz_time = g_strdup(buf);
		}
	} else {
		ofono_error("Error during set nitz time");
		netreg->nitz_time = NULL;
		return;
	}

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"NITZ", DBUS_TYPE_STRING,
					&nitz_str);

}

void __ofono_netreg_set_base_station_name(struct ofono_netreg *netreg,
						const char *name)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(netreg->atom);
	const char *base_station = name ? name : "";

	/* Cell ID changed, but we don't have a cell name, nothing to do */
	if (netreg->base_station == NULL && name == NULL)
		return;

	if (netreg->base_station)
		g_free(netreg->base_station);

	if (name == NULL) {
		netreg->base_station = NULL;

		/*
		 * We just got unregistered, set name to NULL
		 * but don't emit signal
		 */
		if (netreg->current_operator == NULL)
			return;
	} else {
		netreg->base_station = g_strdup(name);
	}

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"BaseStation", DBUS_TYPE_STRING,
					&base_station);
}

unsigned int __ofono_netreg_add_status_watch(struct ofono_netreg *netreg,
				ofono_netreg_status_notify_cb_t notify,
				void *data, ofono_destroy_func destroy)
{
	struct ofono_watchlist_item *item;

	DBG("%p", netreg);

	if (netreg == NULL)
		return 0;

	if (notify == NULL)
		return 0;

	item = g_new0(struct ofono_watchlist_item, 1);

	item->notify = notify;
	item->destroy = destroy;
	item->notify_data = data;

	return __ofono_watchlist_add_item(netreg->status_watches, item);
}

gboolean __ofono_netreg_remove_status_watch(struct ofono_netreg *netreg,
						unsigned int id)
{
	DBG("%p", netreg);

	if (netreg == NULL)
		return FALSE;

	return __ofono_watchlist_remove_item(netreg->status_watches, id);
}

static void notify_status_watches(struct ofono_netreg *netreg)
{
	struct ofono_watchlist_item *item;
	GSList *l;
	ofono_netreg_status_notify_cb_t notify;
	const char *mcc = NULL;
	const char *mnc = NULL;

	if (netreg->status_watches == NULL)
		return;

	if (netreg->current_operator) {
		mcc = netreg->current_operator->mcc;
		mnc = netreg->current_operator->mnc;
	}

	for (l = netreg->status_watches->items; l; l = l->next) {
		item = l->data;
		notify = item->notify;

		notify(netreg->status, netreg->location, netreg->cellid,
			netreg->technology, mcc, mnc, item->notify_data);
	}
}

static void reset_available(struct network_operator_data *old,
				const struct ofono_network_operator *new)
{
	if (old == NULL)
		return;

	if (new == NULL || network_operator_compare(old, new) != 0)
		set_network_operator_status(old, OPERATOR_STATUS_AVAILABLE);
}


void report_roaming_country_info(char* mcc)
{
	if(!strcmp(mcc, "454")) {
		OFONO_DFX_ROAMING_INFO(OFONO_HONGKONG);
	} else if (!strcmp(mcc, "455")) {
		OFONO_DFX_ROAMING_INFO(OFONO_MACAU);
	} else {
		OFONO_DFX_ROAMING_INFO(OFONO_COUNTRY_UNKNOW);
	}
}

static void current_operator_callback(const struct ofono_error *error,
				const struct ofono_network_operator *current,
				void *data)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_netreg *netreg = data;
	const char *path = __ofono_atom_get_path(netreg->atom);
	GSList *op = NULL;

	ofono_debug("%s, %p, %p", __func__, netreg, netreg->current_operator);

	/*
	 * Sometimes we try to query COPS right when we roam off the cell,
	 * in which case the operator information frequently comes in bogus.
	 * We ignore it here
	 */
	if (netreg->status != NETWORK_REGISTRATION_STATUS_REGISTERED &&
			netreg->status != NETWORK_REGISTRATION_STATUS_ROAMING)
		current = NULL;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		ofono_error("Error during current operator");
		return;
	}

	if (netreg->current_operator == NULL && current == NULL)
		return;

	/* We got a new network operator, reset the previous one's status */
	/* It will be updated properly later */
	reset_available(netreg->current_operator, current);

	if (current)
		op = g_slist_find_custom(netreg->operator_list, current,
					network_operator_compare);

	if (op) {
		struct network_operator_data *opd = op->data;
		unsigned int techs = opd->techs;

		if (current->tech != -1) {
			techs |= 1 << current->tech;
			set_network_operator_techs(opd, techs);
		}

		set_network_operator_status(opd, OPERATOR_STATUS_CURRENT);
		set_network_operator_name(opd, current->name);

		if (netreg->current_operator == op->data)
			return;

		netreg->current_operator = op->data;
		goto emit;
	}

	if (current) {
		struct network_operator_data *opd;

		opd = network_operator_create(current);

		if (opd->mcc[0] != '\0' && opd->mnc[0] != '\0' &&
				!network_operator_dbus_register(netreg, opd)) {
			g_free(opd);
			return;
		} else
			opd->netreg = netreg;

		netreg->current_operator = opd;
		netreg->operator_list = g_slist_append(netreg->operator_list,
							opd);
	} else {
		/* We don't free this here because operator is registered */
		/* Taken care of elsewhere */
		netreg->current_operator = NULL;
	}

emit:
	netreg_emit_operator_display_name(netreg);

	if (netreg->current_operator) {
		if (netreg->current_operator->mcc[0] != '\0') {
			const char *mcc = netreg->current_operator->mcc;
			ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"MobileCountryCode",
					DBUS_TYPE_STRING, &mcc);
			if (netreg->status == NETWORK_REGISTRATION_STATUS_ROAMING) {
				report_roaming_country_info(netreg->current_operator->mcc);
			}
		}

		if (netreg->current_operator->mnc[0] != '\0') {
			const char *mnc = netreg->current_operator->mnc;
			ofono_dbus_signal_property_changed(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					"MobileNetworkCode",
					DBUS_TYPE_STRING, &mnc);
		}
	}

	notify_status_watches(netreg);
}

static void signal_strength_callback(const struct ofono_error *error,
					int strength, void *data)
{
	struct ofono_netreg *netreg = data;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		netreg->signal_strength_changed = FALSE;
		ofono_error("Error during signal strength query");
		return;
	}

	ofono_netreg_strength_notify(netreg, strength);
}

static void notify_emulator_status(struct ofono_atom *atom, void *data)
{
	struct ofono_emulator *em = __ofono_atom_get_data(atom);

	switch (GPOINTER_TO_INT(data)) {
	case NETWORK_REGISTRATION_STATUS_REGISTERED:
		ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_SERVICE, 1);
		ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_ROAMING, 0);
		break;
	case NETWORK_REGISTRATION_STATUS_ROAMING:
		ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_SERVICE, 1);
		ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_ROAMING, 1);
		break;
	default:
		ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_SERVICE, 0);
		ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_ROAMING, 0);
	}
}

void start_record_oos_time(struct ofono_netreg *netreg)
{
	ofono_debug("%s", __func__);
	if (netreg->oos_start_time.tv_sec == 0 &&
	    netreg->oos_start_time.tv_nsec == 0) {
		clock_gettime(CLOCK_MONOTONIC, &netreg->oos_start_time);
	} else {
		ofono_error("unexpect status in %s", __func__);
	}
}

void stop_record_oos_time(struct ofono_netreg *netreg)
{
	ofono_debug("%s:%d", __func__,
		    netreg->oos_start_time.tv_sec != 0 ||
			    netreg->oos_start_time.tv_nsec != 0);
	if (netreg->oos_start_time.tv_sec != 0 ||
	    netreg->oos_start_time.tv_nsec != 0) {
		struct timespec stop_time;

		clock_gettime(CLOCK_MONOTONIC, &stop_time);
		int temp_value =
			stop_time.tv_sec - netreg->oos_start_time.tv_sec;
		if (netreg->oos_by_radio_on_flag &&
		    temp_value < NORMAL_REGISTER_DURATION) {
			netreg->oos_by_radio_on_flag = FALSE;
			ofono_debug("%s ignore oos duration", __func__);
		} else {
			netreg->oos_duration =
				netreg->oos_duration + temp_value;
		}
		memset(&netreg->oos_start_time, 0,
		       sizeof(netreg->oos_start_time));
	}
}

static gboolean report_oos_duration(gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;

	ofono_debug("%s:%d,%d", __func__,
		    netreg->oos_start_time.tv_sec != 0 ||
			    netreg->oos_start_time.tv_nsec != 0,
		    netreg->oos_duration != 0);
	if (netreg->oos_start_time.tv_sec != 0 ||
	    netreg->oos_start_time.tv_nsec != 0) {
		stop_record_oos_time(netreg);
		start_record_oos_time(netreg);
	}
	if (netreg->oos_duration != 0) {
		OFONO_DFX_OOS_DURATION_INFO(netreg->oos_duration);
	}
	netreg->oos_duration = 0;
	return TRUE;
}

void update_signal_level_duration(struct ofono_netreg *netreg)
{
	int current_signal_level;
	struct timespec update_time;

	ofono_debug("update_signal_level_duration:%d,%d", netreg->status,
		    netreg->current_signal_level);
	if ((netreg->status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
	     netreg->status == NETWORK_REGISTRATION_STATUS_ROAMING) &&
	    netreg->radio_status == RADIO_STATUS_ON) {
		current_signal_level =
			ofono_netreg_get_signal_strength_level(netreg);
	} else {
		current_signal_level = SIGNAL_STRENGTH_UNKNOWN;
	}
	clock_gettime(CLOCK_MONOTONIC, &update_time);

	if (netreg->current_signal_level != SIGNAL_STRENGTH_UNKNOWN) {
		int temp_value = update_time.tv_sec -
				 netreg->signal_level_start_time.tv_sec;
		netreg->signal_level_duration[netreg->current_signal_level] =
			temp_value + netreg->signal_level_duration
					     [netreg->current_signal_level];
	}
	netreg->signal_level_start_time = update_time;
	netreg->current_signal_level = current_signal_level;
}

void ofono_netreg_status_notify(struct ofono_netreg *netreg, int status,
			int lac, int ci, int tech, int denial)
{
	int old_status = netreg->status;

	if (netreg == NULL)
		return;

	ofono_debug("%s status %d tech %d lac %d ci %d denial %d",
		__ofono_atom_get_path(netreg->atom), status, tech, lac, ci, denial);

	if (netreg->status != status) {
		struct ofono_modem *modem;

		if ((status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
		     status == NETWORK_REGISTRATION_STATUS_ROAMING) &&
		    (netreg->status != NETWORK_REGISTRATION_STATUS_REGISTERED &&
		     netreg->status != NETWORK_REGISTRATION_STATUS_ROAMING)) {
			stop_record_oos_time(netreg);
		} else {
			if ((netreg->status ==
				     NETWORK_REGISTRATION_STATUS_REGISTERED ||
			     netreg->status ==
				     NETWORK_REGISTRATION_STATUS_ROAMING) &&
			    (status != NETWORK_REGISTRATION_STATUS_REGISTERED &&
			     status != NETWORK_REGISTRATION_STATUS_ROAMING) &&
			    netreg->radio_status == RADIO_STATUS_ON) {
				OFONO_DFX_OOS_INFO();
				start_record_oos_time(netreg);
			}
		}

		set_registration_status(netreg, status);

		update_signal_level_duration(netreg);

		modem = __ofono_atom_get_modem(netreg->atom);
		__ofono_modem_foreach_registered_atom(modem,
					OFONO_ATOM_TYPE_EMULATOR_HFP,
					notify_emulator_status,
					GINT_TO_POINTER(netreg->status));
	}

	if (netreg->location != lac)
		set_registration_location(netreg, lac);

	if (netreg->denial_reason != denial)
		set_registration_denial_reason(netreg, denial);

	if (netreg->cellid != ci)
		set_registration_cellid(netreg, ci);

	if (netreg->technology != tech || old_status != status)
		set_registration_technology(netreg, tech);

	if (netreg->status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
		netreg->status == NETWORK_REGISTRATION_STATUS_ROAMING) {
		if (netreg->driver->current_operator != NULL)
			netreg->driver->current_operator(netreg,
					current_operator_callback, netreg);

		ofono_netreg_poll_signal_strength(netreg);
	} else {
		struct ofono_error error;

		error.type = OFONO_ERROR_TYPE_NO_ERROR;
		error.error = 0;

		current_operator_callback(&error, NULL, netreg);
		__ofono_netreg_set_base_station_name(netreg, NULL);

		netreg->signal_strength = -1;
	}

	notify_status_watches(netreg);
}

void ofono_netreg_time_notify(struct ofono_netreg *netreg,
				struct ofono_network_time *info)
{
	struct ofono_modem *modem = __ofono_atom_get_modem(netreg->atom);

	if (info == NULL)
		return;

	ofono_debug("net time %d-%02d-%02d %02d:%02d:%02d utcoff %d dst %d",
		info->year, info->mon, info->mday,
		info->hour, info->min, info->sec,
		info->utcoff, info->dst);

	set_nitz_time(netreg, info);

	__ofono_nettime_info_received(modem, info);
}

static void sim_csp_read_cb(int ok, int total_length, int record,
				const unsigned char *data,
				int record_length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	int i = 0;

	if (!ok)
		return;

	if (total_length < 18)
		return;

	/*
	 * According to CPHS 4.2, EFcsp is an array of two-byte service
	 * entries, each consisting of a one byte service group
	 * identifier followed by 8 bits; each bit is indicating
	 * availability of a specific service or feature.
	 *
	 * The PLMN mode bit, if present, indicates whether manual
	 * operator selection should be disabled or enabled. When
	 * unset, the device is forced to automatic mode; when set,
	 * manual selection is to be enabled. The latter is also the
	 * default.
	 */
	while (i < total_length &&
			data[i] != SIM_CSP_ENTRY_VALUE_ADDED_SERVICES)
		i += 2;

	if (i == total_length)
		return;

	if ((data[i + 1] & 0x80) != 0) {
		if (netreg->mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
			set_registration_mode(netreg,
						NETWORK_REGISTRATION_MODE_AUTO);

		return;
	}

	set_registration_mode(netreg, NETWORK_REGISTRATION_MODE_AUTO_ONLY);
}

static void sim_csp_changed(int id, void *userdata)
{
	struct ofono_netreg *netreg = userdata;

	ofono_sim_read(netreg->sim_context, SIM_EF_CPHS_CSP_FILEID,
			OFONO_SIM_FILE_STRUCTURE_TRANSPARENT,
			sim_csp_read_cb, netreg);
}

static void init_registration_status(const struct ofono_error *error,
					int status, int lac, int ci, int tech, int denial,
					void *data)
{
	struct ofono_netreg *netreg = data;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		ofono_error("Error during registration status query");
		return;
	}

	ofono_netreg_status_notify(netreg, status, lac, ci, tech, denial);

	/*
	 * Bootstrap our signal strength value without waiting for the
	 * stack to report it
	 */
	if (netreg->status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
		netreg->status == NETWORK_REGISTRATION_STATUS_ROAMING) {
		if (netreg->driver->strength != NULL)
			netreg->driver->strength(netreg,
					signal_strength_callback, netreg);
	}

	if (netreg->mode != NETWORK_REGISTRATION_MODE_MANUAL &&
		(status == NETWORK_REGISTRATION_STATUS_NOT_REGISTERED ||
			status == NETWORK_REGISTRATION_STATUS_DENIED ||
			status == NETWORK_REGISTRATION_STATUS_UNKNOWN)) {
		if (netreg->driver->register_auto != NULL)
			netreg->driver->register_auto(netreg, init_register,
							netreg);
	}

	if (netreg->driver->register_manual == NULL) {
		set_registration_mode(netreg,
					NETWORK_REGISTRATION_MODE_AUTO_ONLY);
		return;
	}
}

static void notify_emulator_strength(struct ofono_atom *atom, void *data)
{
	struct ofono_emulator *em = __ofono_atom_get_data(atom);
	int val = 0;

	if (GPOINTER_TO_INT(data) > 0)
		val = (GPOINTER_TO_INT(data) - 1) / 20 + 1;

	ofono_emulator_set_indicator(em, OFONO_EMULATOR_IND_SIGNAL, val);
}

static gboolean report_signal_level_info(gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;

	update_signal_level_duration(netreg);
	if (netreg->signal_level_duration[0] != 0 ||
	    netreg->signal_level_duration[1] != 0 ||
	    netreg->signal_level_duration[2] != 0 ||
	    netreg->signal_level_duration[3] != 0 ||
	    netreg->signal_level_duration[4] != 0 ||
	    netreg->signal_level_duration[5] != 0) {
		OFONO_DFX_SIGNAL_LEVEL_DURATION(
			netreg->signal_level_duration[0],
			netreg->signal_level_duration[1],
			netreg->signal_level_duration[2],
			netreg->signal_level_duration[3],
			netreg->signal_level_duration[4],
			netreg->signal_level_duration[5]);
	}
	memset(netreg->signal_level_duration, 0,
	       sizeof(netreg->signal_level_duration));
	return TRUE;
}

static gboolean report_rat_info(gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;

	ofono_debug("%s", __func__);
	if (netreg->rat_start_time.tv_sec != 0 ||
	    netreg->rat_start_time.tv_nsec != 0) {
		struct timespec update_time;
		int temp_value;

		clock_gettime(CLOCK_MONOTONIC, &update_time);
		temp_value = update_time.tv_sec - netreg->rat_start_time.tv_sec;
		netreg->rat_duration[netreg->current_rat] =
			temp_value + netreg->rat_duration[netreg->current_rat];
		netreg->rat_start_time = update_time;
	}
	if (netreg->rat_duration[0] != 0 || netreg->rat_duration[1] != 0 ||
	    netreg->rat_duration[2] != 0 || netreg->rat_duration[3] != 0) {
		OFONO_DFX_RAT_DURATION(
			netreg->rat_duration[0], netreg->rat_duration[1],
			netreg->rat_duration[2], netreg->rat_duration[3]);
	}
	memset(netreg->rat_duration, 0, sizeof(netreg->rat_duration));
	return TRUE;
}

static void netreg_radio_state_change(int state, void *data)
{
	struct ofono_atom *atom = data;
	struct ofono_netreg *netreg = __ofono_atom_get_data(atom);
	int old_state = netreg->radio_status;

	netreg->radio_status = state;

	ofono_debug("netreg_radio_state_change:%d", state);

	if (state == RADIO_STATUS_ON) {
		netreg->oos_by_radio_on_flag = TRUE;
		start_record_oos_time(netreg);
	}
	if ((state == RADIO_STATUS_OFF || state == RADIO_STATUS_UNAVAILABLE) &&
	    old_state != RADIO_STATUS_UNKNOWN) {
		update_rat_duration(netreg, netreg->current_rat);
		update_signal_level_duration(netreg);
	}
	if (state == RADIO_STATUS_OFF && old_state != RADIO_STATUS_UNKNOWN) {
		stop_record_oos_time(netreg);
	}
}

void ofono_netreg_strength_notify(struct ofono_netreg *netreg, int strength)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem;

	if (netreg->signal_strength_changed)
		netreg_emit_signal_strength_changed(netreg);

	if (netreg->signal_strength != strength) {
		ofono_debug("%s - strength %d", __func__, strength);

		netreg->signal_strength = strength;

		if (strength != -1) {
			const char *path = __ofono_atom_get_path(netreg->atom);
			unsigned char strength_byte = netreg->signal_strength;

			ofono_dbus_signal_property_changed(conn, path,
						OFONO_NETWORK_REGISTRATION_INTERFACE,
						"Strength", DBUS_TYPE_BYTE,
						&strength_byte);
		}

		modem = __ofono_atom_get_modem(netreg->atom);
		__ofono_modem_foreach_registered_atom(modem,
					OFONO_ATOM_TYPE_EMULATOR_HFP,
					notify_emulator_strength,
					GINT_TO_POINTER(netreg->signal_strength));
		ofono_voicecall_update_call_duration(__ofono_atom_find(OFONO_ATOM_TYPE_VOICECALL,
					modem), netreg);
		update_signal_level_duration(netreg);
	}
}

static void sim_opl_read_cb(int ok, int length, int record,
				const unsigned char *data,
				int record_length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	int total;
	GSList *l;

	if (!ok) {
		if (record > 0)
			goto optimize;

		return;
	}

	if (record_length < 8 || length < record_length)
		return;

	total = length / record_length;

	sim_eons_add_opl_record(netreg->eons, data, record_length);

	if (record != total)
		return;

optimize:
	sim_eons_optimize(netreg->eons);

	for (l = netreg->operator_list; l; l = l->next) {
		struct network_operator_data *opd = l->data;
		const struct sim_eons_operator_info *eons_info;

		eons_info = sim_eons_lookup(netreg->eons, opd->mcc, opd->mnc);

		set_network_operator_eons_info(opd, eons_info);
	}
}

static void sim_pnn_read_cb(int ok, int length, int record,
				const unsigned char *data,
				int record_length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	int total;

	if (!ok)
		goto check;

	if (length < 3 || record_length < 3 || length < record_length)
		goto check;

	total = length / record_length;

	if (netreg->eons == NULL)
		netreg->eons = sim_eons_new(total);

	sim_eons_add_pnn_record(netreg->eons, record, data, record_length);

	if (record != total)
		return;

check:
	netreg->flags &= ~NETWORK_REGISTRATION_FLAG_READING_PNN;

	/*
	 * If PNN is not present then OPL is not useful, don't
	 * retrieve it.  If OPL is not there then PNN[1] will
	 * still be used for the HPLMN and/or EHPLMN, if PNN
	 * is present.
	 */
	if (netreg->eons && !sim_eons_pnn_is_empty(netreg->eons))
		ofono_sim_read(netreg->sim_context, SIM_EFOPL_FILEID,
				OFONO_SIM_FILE_STRUCTURE_FIXED,
				sim_opl_read_cb, netreg);
}

static void sim_spdi_read_cb(int ok, int length, int record,
				const unsigned char *data,
				int record_length, void *user_data)
{
	struct ofono_netreg *netreg = user_data;

	if (!ok)
		return;

	netreg->spdi = sim_spdi_new(data, length);

	if (netreg->current_operator == NULL)
		return;

	if (netreg->status != NETWORK_REGISTRATION_STATUS_ROAMING)
		return;

	if (!sim_spdi_lookup(netreg->spdi, netreg->current_operator->mcc,
				netreg->current_operator->mnc))
		return;

	netreg_emit_operator_display_name(netreg);
}

static void sim_spn_display_condition_parse(struct ofono_netreg *netreg,
						guint8 dcbyte)
{
	if (dcbyte & SIM_EFSPN_DC_HOME_PLMN_BIT)
		netreg->flags |= NETWORK_REGISTRATION_FLAG_HOME_SHOW_PLMN;

	if (!(dcbyte & SIM_EFSPN_DC_ROAMING_SPN_BIT))
		netreg->flags |= NETWORK_REGISTRATION_FLAG_ROAMING_SHOW_SPN;
}

static void spn_read_cb(const char *spn, const char *dc, void *data)
{
	struct ofono_netreg *netreg = data;

	netreg->flags &= ~(NETWORK_REGISTRATION_FLAG_HOME_SHOW_PLMN |
				NETWORK_REGISTRATION_FLAG_ROAMING_SHOW_SPN);

	if (dc)
		sim_spn_display_condition_parse(netreg, *dc);

	if (netreg->current_operator)
		netreg_emit_operator_display_name(netreg);
}

static void fill_signal_strength_with_invalid(struct ofono_signal_strength *signal_strength)
{
	ofono_debug("%s", __func__);

	if (signal_strength) {
		if (signal_strength->gw_signal_strength) {
			signal_strength->gw_signal_strength->strength = INT_MAX;
			signal_strength->gw_signal_strength->rssi = INT_MAX;
			signal_strength->gw_signal_strength->ber = INT_MAX;
		}

		if (signal_strength->lte_signal_strength) {
			signal_strength->lte_signal_strength->strength = INT_MAX;
			signal_strength->lte_signal_strength->rssi = INT_MAX;
			signal_strength->lte_signal_strength->rsrp = INT_MAX;
			signal_strength->lte_signal_strength->rsrq = INT_MAX;
			signal_strength->lte_signal_strength->rssnr = INT_MAX;
			signal_strength->lte_signal_strength->cqi = INT_MAX;
		}

		signal_strength->level = SIGNAL_STRENGTH_UNKNOWN;
	}
}

int ofono_netreg_get_location(struct ofono_netreg *netreg)
{
	if (netreg == NULL)
		return -1;

	return netreg->location;
}

int ofono_netreg_get_cellid(struct ofono_netreg *netreg)
{
	if (netreg == NULL)
		return -1;

	return netreg->cellid;
}

int ofono_netreg_get_status(struct ofono_netreg *netreg)
{
	if (netreg == NULL)
		return -1;

	return netreg->status;
}

int ofono_netreg_get_technology(struct ofono_netreg *netreg)
{
	if (netreg == NULL)
		return -1;

	return netreg->technology;
}

const char *ofono_netreg_get_mcc(struct ofono_netreg *netreg)
{
	if (netreg == NULL)
		return NULL;

	if (netreg->current_operator == NULL)
		return NULL;

	return netreg->current_operator->mcc;
}

const char *ofono_netreg_get_mnc(struct ofono_netreg *netreg)
{
	if (netreg == NULL)
		return NULL;

	if (netreg->current_operator == NULL)
		return NULL;

	return netreg->current_operator->mnc;
}

int ofono_netreg_get_signal_strength_level(struct ofono_netreg *netreg)
{
	if (netreg == NULL || netreg->signal_strength_data == NULL)
		return SIGNAL_STRENGTH_UNKNOWN;

	return netreg->signal_strength_data->level;
}

void ofono_netreg_poll_signal_strength(struct ofono_netreg *netreg)
{
	if (netreg == NULL || netreg->driver == NULL || netreg->driver->strength == NULL)
		return;

	ofono_debug("%s", __func__);
	netreg->driver->strength(netreg,
			signal_strength_callback, netreg);
}

void ofono_netreg_set_signal_strength(struct ofono_netreg *netreg,
	int ril_tech, const struct ofono_signal_strength *ril_strength)
{
	int ber, rssi, rsrp, rsrq, rssnr, cqi;

	if (netreg->signal_strength_data == NULL
		|| ril_strength == NULL)
		goto done;

	ofono_debug("%s - tech = %d", __func__, ril_tech);
	if (ril_tech == RADIO_TECH_UMTS) {
		if (ril_strength->gw_signal_strength == NULL
			|| netreg->signal_strength_data->gw_signal_strength == NULL)
			goto done;

		rssi = in_range_or_unavailable(
			get_rssi_dbm_from_asu(
				ril_strength->gw_signal_strength->strength), -113, -51);
		if (netreg->signal_strength_data->gw_signal_strength->rssi == rssi) {
			ofono_debug("%s - old rssi = %d, new rssi = %d", __func__,
				netreg->signal_strength_data->gw_signal_strength->rssi, rssi);
			goto done;
		}

		ber = in_range_or_unavailable(
			ril_strength->gw_signal_strength->ber, 0, 7);

		netreg->signal_strength_data->gw_signal_strength->rssi = rssi;
		netreg->signal_strength_data->gw_signal_strength->ber = ber;

		netreg->signal_strength_data->level = get_signal_level_from_rssi(rssi);
	} else if (ril_tech == RADIO_TECH_LTE) {
		if (ril_strength->lte_signal_strength == NULL
			|| netreg->signal_strength_data->lte_signal_strength == NULL)
			goto done;

		rsrp = in_range_or_unavailable(
			-ril_strength->lte_signal_strength->rsrp, -140, -43);
		if (netreg->signal_strength_data->lte_signal_strength->rsrp == rsrp) {
			ofono_debug("%s - old rsrp = %d, new rsrp = %d", __func__,
				netreg->signal_strength_data->lte_signal_strength->rsrp, rsrp);
			goto done;
		}

		rssi = in_range_or_unavailable(
			get_rssi_dbm_from_asu(
				ril_strength->lte_signal_strength->strength), -113, -51);
		rssnr = in_range_or_unavailable(
			convert_rssnr_unit_from_ten_db_to_db(
				ril_strength->lte_signal_strength->rssnr), -20, 30);
		rsrq = in_range_or_unavailable(
			-ril_strength->lte_signal_strength->rsrq, -34, 3);
		cqi = in_range_or_unavailable(
			ril_strength->lte_signal_strength->cqi, 0, 15);

		netreg->signal_strength_data->lte_signal_strength->rssi = rssi;
		netreg->signal_strength_data->lte_signal_strength->rsrp = rsrp;
		netreg->signal_strength_data->lte_signal_strength->rsrq = rsrq;
		netreg->signal_strength_data->lte_signal_strength->rssnr = rssnr;
		netreg->signal_strength_data->lte_signal_strength->cqi = cqi;

		netreg->signal_strength_data->level = get_signal_level_from_rsrp(rsrp);
	} else {
		fill_signal_strength_with_invalid(netreg->signal_strength_data);
	}

	netreg->signal_strength_changed = TRUE;

	return;

done:
	netreg->signal_strength_changed = FALSE;
}

int ofono_netreg_driver_register(const struct ofono_netreg_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	if (d->probe == NULL)
		return -EINVAL;

	g_drivers = g_slist_prepend(g_drivers, (void *) d);

	return 0;
}

void ofono_netreg_driver_unregister(const struct ofono_netreg_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	g_drivers = g_slist_remove(g_drivers, (void *) d);
}

static void emulator_remove_handler(struct ofono_atom *atom, void *data)
{
	struct ofono_emulator *em = __ofono_atom_get_data(atom);

	ofono_emulator_remove_handler(em, data);
}

static void netreg_unregister(struct ofono_atom *atom)
{
	struct ofono_netreg *netreg = __ofono_atom_get_data(atom);
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(atom);
	const char *path = __ofono_atom_get_path(atom);
	GSList *l;

	__ofono_modem_foreach_registered_atom(modem,
						OFONO_ATOM_TYPE_EMULATOR_HFP,
						notify_emulator_status,
						GINT_TO_POINTER(0));
	__ofono_modem_foreach_registered_atom(modem,
						OFONO_ATOM_TYPE_EMULATOR_HFP,
						notify_emulator_strength,
						GINT_TO_POINTER(0));

	__ofono_modem_foreach_registered_atom(modem,
						OFONO_ATOM_TYPE_EMULATOR_HFP,
						emulator_remove_handler,
						"+COPS");

	__ofono_modem_remove_atom_watch(modem, netreg->hfp_watch);

	__ofono_watchlist_free(netreg->status_watches);
	netreg->status_watches = NULL;

	for (l = netreg->operator_list; l; l = l->next) {
		struct network_operator_data *opd = l->data;

		if (opd->mcc[0] == '\0' && opd->mnc[0] == '\0') {
			g_free(opd);
			continue;
		}

		network_operator_dbus_unregister(netreg, l->data);
	}

	g_slist_free(netreg->operator_list);
	netreg->operator_list = NULL;

	if (netreg->base_station) {
		g_free(netreg->base_station);
		netreg->base_station = NULL;
	}

	if (netreg->settings) {
		storage_close(netreg->imsi, SETTINGS_STORE,
				netreg->settings, TRUE);

		g_free(netreg->imsi);
		netreg->imsi = NULL;
		netreg->settings = NULL;
	}

	if (netreg->spn_watch) {
		ofono_sim_remove_spn_watch(netreg->sim, &netreg->spn_watch);
		netreg->spn_watch = 0;
	}

	if (netreg->sim_context) {
		if (netreg->sim_efpnn_watch) {
			ofono_sim_remove_file_watch(netreg->sim_context, netreg->sim_efpnn_watch);
			netreg->sim_efpnn_watch = 0;
		}

		if (netreg->sim_efopl_watch) {
			ofono_sim_remove_file_watch(netreg->sim_context, netreg->sim_efopl_watch);
			netreg->sim_efopl_watch = 0;
		}

		if (netreg->sim_efcphs_csp_watch) {
			ofono_sim_remove_file_watch(netreg->sim_context, netreg->sim_efcphs_csp_watch);
			netreg->sim_efcphs_csp_watch = 0;
		}

		ofono_sim_context_free(netreg->sim_context);
		netreg->sim_context = NULL;
	}

	if (netreg->sim_state_watch) {
		ofono_sim_remove_state_watch(netreg->sim, netreg->sim_state_watch);
		netreg->sim_state_watch = 0;
	}

	if (netreg->sim_watch) {
		__ofono_modem_remove_atom_watch(modem, netreg->sim_watch);
		netreg->sim_watch = 0;
	}

	if (netreg->radio_online_watch) {
		__ofono_modem_remove_online_watch(modem, netreg->radio_online_watch);
		netreg->radio_online_watch = 0;
	}

	netreg->sim = NULL;

	g_dbus_unregister_interface(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE);
	ofono_modem_remove_interface(modem,
					OFONO_NETWORK_REGISTRATION_INTERFACE);

	if (netreg->signal_strength_data) {
		if (netreg->signal_strength_data->gw_signal_strength) {
			g_free(netreg->signal_strength_data->gw_signal_strength);
			netreg->signal_strength_data->gw_signal_strength = NULL;
		}

		if (netreg->signal_strength_data->lte_signal_strength) {
			g_free(netreg->signal_strength_data->lte_signal_strength);
			netreg->signal_strength_data->lte_signal_strength = NULL;
		}

		g_free(netreg->signal_strength_data);
		netreg->signal_strength_data = NULL;
	}

	report_oos_duration(netreg);
	g_source_remove(netreg->report_oos_time_id);

	report_signal_level_info(netreg);
	g_source_remove(netreg->signal_level_time_id);

	report_rat_info(netreg);
	g_source_remove(netreg->rat_report_time_id);
}

static void netreg_remove(struct ofono_atom *atom)
{
	struct ofono_netreg *netreg = __ofono_atom_get_data(atom);

	DBG("atom: %p", atom);

	if (netreg == NULL)
		return;

	if (netreg->pending != NULL) {
		DBusMessage *reply = __ofono_error_failed(netreg->pending);
		__ofono_dbus_pending_reply(&netreg->pending, reply);
	}

	if (netreg->driver != NULL && netreg->driver->remove != NULL)
		netreg->driver->remove(netreg);

	sim_eons_free(netreg->eons);
	sim_spdi_free(netreg->spdi);

	g_free(netreg);
}

struct ofono_netreg *ofono_netreg_create(struct ofono_modem *modem,
					unsigned int vendor,
					const char *driver,
					void *data)
{
	struct ofono_netreg *netreg;
	GSList *l;

	if (driver == NULL)
		return NULL;

	netreg = g_try_new0(struct ofono_netreg, 1);

	if (netreg == NULL)
		return NULL;

	netreg->status = NETWORK_REGISTRATION_STATUS_UNKNOWN;
	netreg->location = -1;
	netreg->cellid = -1;
	netreg->technology = -1;
	netreg->signal_strength = -1;
	netreg->signal_strength_data = NULL;

	netreg->atom = __ofono_modem_add_atom(modem, OFONO_ATOM_TYPE_NETREG,
						netreg_remove, netreg);

	__ofono_atom_add_radio_state_watch(netreg->atom,
					   netreg_radio_state_change);

	for (l = g_drivers; l; l = l->next) {
		const struct ofono_netreg_driver *drv = l->data;

		if (g_strcmp0(drv->name, driver))
			continue;

		if (drv->probe(netreg, vendor, data) < 0)
			continue;

		netreg->driver = drv;
		break;
	}

	return netreg;
}

static void netreg_load_settings(struct ofono_netreg *netreg)
{
	const char *imsi;
	char *strmode;
	gboolean upgrade = FALSE;

	if (netreg->mode == NETWORK_REGISTRATION_MODE_AUTO_ONLY)
		return;

	imsi = ofono_sim_get_imsi(netreg->sim);
	if (imsi == NULL)
		return;

	netreg->settings = storage_open(imsi, SETTINGS_STORE);

	if (netreg->settings == NULL)
		return;

	netreg->imsi = g_strdup(imsi);

	strmode = g_key_file_get_string(netreg->settings, SETTINGS_GROUP,
					"Mode", NULL);

	if (strmode == NULL)
		upgrade = TRUE;
	else if (g_str_equal(strmode, "auto"))
		netreg->mode = NETWORK_REGISTRATION_MODE_AUTO;
	else if (g_str_equal(strmode, "manual"))
		netreg->mode = NETWORK_REGISTRATION_MODE_MANUAL;
	else {
		int mode;

		mode = g_key_file_get_integer(netreg->settings, SETTINGS_GROUP,
						"Mode", NULL);

		switch (mode) {
		case NETWORK_REGISTRATION_MODE_AUTO:
		case NETWORK_REGISTRATION_MODE_MANUAL:
			netreg->mode = mode;
			break;
		}

		upgrade = TRUE;
	}

	g_free(strmode);

	if (upgrade == FALSE)
		return;

	if (netreg->mode == NETWORK_REGISTRATION_MODE_MANUAL)
		strmode = "manual";
	else
		strmode = "auto";

	g_key_file_set_string(netreg->settings, SETTINGS_GROUP,
				"Mode", strmode);
}

static void sim_pnn_opl_changed(int id, void *userdata)
{
	struct ofono_netreg *netreg = userdata;
	GSList *l;

	if (netreg->flags & NETWORK_REGISTRATION_FLAG_READING_PNN)
		return;
	/*
	 * Free references to structures on the netreg->eons list and
	 * update the operator info on D-bus.  If EFpnn/EFopl read succeeds,
	 * operator info will be updated again, otherwise it won't be
	 * updated again.
	 */
	for (l = netreg->operator_list; l; l = l->next)
		set_network_operator_eons_info(l->data, NULL);

	sim_eons_free(netreg->eons);
	netreg->eons = NULL;

	netreg->flags |= NETWORK_REGISTRATION_FLAG_READING_PNN;
	ofono_sim_read(netreg->sim_context, SIM_EFPNN_FILEID,
			OFONO_SIM_FILE_STRUCTURE_FIXED,
			sim_pnn_read_cb, netreg);
}

static void sim_spdi_changed(int id, void *userdata)
{
	struct ofono_netreg *netreg = userdata;

	sim_spdi_free(netreg->spdi);
	netreg->spdi = NULL;

	if (netreg->current_operator &&
			netreg->status == NETWORK_REGISTRATION_STATUS_ROAMING)
		netreg_emit_operator_display_name(netreg);

	ofono_sim_read(netreg->sim_context, SIM_EFSPDI_FILEID,
			OFONO_SIM_FILE_STRUCTURE_TRANSPARENT,
			sim_spdi_read_cb, netreg);
}

static void sim_state_watch(enum ofono_sim_state new_state, void *user)
{
	struct ofono_netreg *netreg = user;

	if (netreg->sim == NULL)
		return;

	ofono_info("network - %s, sim_state : %d", __func__, new_state);

	switch (new_state) {
	case OFONO_SIM_STATE_INSERTED:
		break;
	case OFONO_SIM_STATE_NOT_PRESENT:
	case OFONO_SIM_STATE_RESETTING:
	case OFONO_SIM_STATE_ERROR:
		if (netreg->settings) {
			storage_close(netreg->imsi, SETTINGS_STORE,
					netreg->settings, TRUE);

			g_free(netreg->imsi);
			netreg->imsi = NULL;
			netreg->settings = NULL;
		}

		if (netreg->spn_watch) {
			ofono_sim_remove_spn_watch(netreg->sim, &netreg->spn_watch);
			netreg->spn_watch = 0;
		}

		if (netreg->sim_context) {
			if (netreg->sim_efpnn_watch) {
				ofono_sim_remove_file_watch(netreg->sim_context, netreg->sim_efpnn_watch);
				netreg->sim_efpnn_watch = 0;
			}

			if (netreg->sim_efopl_watch) {
				ofono_sim_remove_file_watch(netreg->sim_context, netreg->sim_efopl_watch);
				netreg->sim_efopl_watch = 0;
			}

			if (netreg->sim_efcphs_csp_watch) {
				ofono_sim_remove_file_watch(netreg->sim_context, netreg->sim_efcphs_csp_watch);
				netreg->sim_efcphs_csp_watch = 0;
			}

			ofono_sim_context_free(netreg->sim_context);
			netreg->sim_context = NULL;
		}

		break;
	case OFONO_SIM_STATE_READY:
		netreg->sim_context = ofono_sim_context_create(netreg->sim);
		netreg_load_settings(netreg);

		netreg->flags |= NETWORK_REGISTRATION_FLAG_READING_PNN;
		ofono_sim_read(netreg->sim_context, SIM_EFPNN_FILEID,
				OFONO_SIM_FILE_STRUCTURE_FIXED,
				sim_pnn_read_cb, netreg);
		netreg->sim_efpnn_watch = ofono_sim_add_file_watch(
						netreg->sim_context, SIM_EFPNN_FILEID,
						sim_pnn_opl_changed, netreg,
						NULL);
		netreg->sim_efopl_watch = ofono_sim_add_file_watch(
						netreg->sim_context, SIM_EFOPL_FILEID,
						sim_pnn_opl_changed, netreg,
						NULL);

		ofono_sim_add_spn_watch(netreg->sim, &netreg->spn_watch,
						spn_read_cb, netreg, NULL);

		if (__ofono_sim_service_available(netreg->sim,
				SIM_UST_SERVICE_PROVIDER_DISPLAY_INFO,
				SIM_SST_SERVICE_PROVIDER_DISPLAY_INFO)) {
			ofono_sim_read(netreg->sim_context, SIM_EFSPDI_FILEID,
					OFONO_SIM_FILE_STRUCTURE_TRANSPARENT,
					sim_spdi_read_cb, netreg);

			ofono_sim_add_file_watch(netreg->sim_context,
							SIM_EFSPDI_FILEID,
							sim_spdi_changed,
							netreg, NULL);
		}
		ofono_sim_read(netreg->sim_context, SIM_EF_CPHS_CSP_FILEID,
				OFONO_SIM_FILE_STRUCTURE_TRANSPARENT,
				sim_csp_read_cb, netreg);

		netreg->sim_efcphs_csp_watch = ofono_sim_add_file_watch(
						netreg->sim_context, SIM_EF_CPHS_CSP_FILEID,
						sim_csp_changed, netreg, NULL);
		break;
	case OFONO_SIM_STATE_LOCKED_OUT:
		break;
	}
}

static void sim_watch(struct ofono_atom *atom,
			enum ofono_atom_watch_condition cond, void *data)
{
	struct ofono_netreg *netreg = data;
	struct ofono_sim *sim = __ofono_atom_get_data(atom);

	if (cond == OFONO_ATOM_WATCH_CONDITION_UNREGISTERED) {
		netreg->sim_state_watch = 0;
		netreg->sim = NULL;
		return;
	}

	netreg->sim = sim;
	netreg->sim_state_watch = ofono_sim_add_state_watch(sim,
							sim_state_watch,
							netreg, NULL);

	sim_state_watch(ofono_sim_get_state(sim), netreg);
}

static void emulator_cops_cb(struct ofono_emulator *em,
			struct ofono_emulator_request *req, void *userdata)
{
	struct ofono_netreg *netreg = userdata;
	struct ofono_error result;
	int val;
	char name[17];
	char buf[32];

	result.error = 0;

	switch (ofono_emulator_request_get_type(req)) {
	case OFONO_EMULATOR_REQUEST_TYPE_SET:
		ofono_emulator_request_next_number(req, &val);
		if (val != 3)
			goto fail;

		ofono_emulator_request_next_number(req, &val);
		if (val != 0)
			goto fail;

		result.type = OFONO_ERROR_TYPE_NO_ERROR;
		ofono_emulator_send_final(em, &result);
		break;

	case OFONO_EMULATOR_REQUEST_TYPE_QUERY:
		strncpy(name, get_operator_display_name(netreg), 16);
		name[16] = '\0';
		sprintf(buf, "+COPS: %d,0,\"%s\"", netreg->mode, name);
		ofono_emulator_send_info(em, buf, TRUE);
		result.type = OFONO_ERROR_TYPE_NO_ERROR;
		ofono_emulator_send_final(em, &result);
		break;

	default:
fail:
		result.type = OFONO_ERROR_TYPE_FAILURE;
		ofono_emulator_send_final(em, &result);
	};
}

static void emulator_hfp_init(struct ofono_atom *atom, void *data)
{
	struct ofono_netreg *netreg = data;
	struct ofono_emulator *em = __ofono_atom_get_data(atom);

	notify_emulator_status(atom, GINT_TO_POINTER(netreg->status));
	notify_emulator_strength(atom,
				GINT_TO_POINTER(netreg->signal_strength));

	ofono_emulator_add_handler(em, "+COPS", emulator_cops_cb, data, NULL);
}

static void emulator_hfp_watch(struct ofono_atom *atom,
				enum ofono_atom_watch_condition cond,
				void *data)
{
	if (cond == OFONO_ATOM_WATCH_CONDITION_REGISTERED)
		emulator_hfp_init(atom, data);
}

static void radio_online_watch_cb(struct ofono_modem *modem,
						ofono_bool_t online,
						void *data)
{
	struct ofono_netreg *netreg = data;

	ofono_debug("network - %s , online : %d", __func__, online);

	if (!online) {
		set_registration_cellid(netreg, -1);
		set_registration_status(netreg, NETWORK_REGISTRATION_STATUS_UNKNOWN);
		set_registration_technology(netreg, -1);
		set_registration_location(netreg, -1);

		if (netreg->signal_strength_data) {
			fill_signal_strength_with_invalid(netreg->signal_strength_data);
			netreg_emit_signal_strength_changed(netreg);
		}

		/*
		 * We don't free it here, because operator is registered as one dbus interface.
		 * Instead just set it to NULL.
		 */
		netreg->current_operator = NULL;
	}
}

void ofono_netreg_register(struct ofono_netreg *netreg)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(netreg->atom);
	const char *path = __ofono_atom_get_path(netreg->atom);

	if (!g_dbus_register_interface(conn, path,
					OFONO_NETWORK_REGISTRATION_INTERFACE,
					network_registration_methods,
					network_registration_signals,
					NULL, netreg, NULL)) {
		ofono_error("Could not create %s interface",
				OFONO_NETWORK_REGISTRATION_INTERFACE);

		return;
	}

	netreg->status_watches = __ofono_watchlist_new(g_free);

	ofono_modem_add_interface(modem, OFONO_NETWORK_REGISTRATION_INTERFACE);

	if (netreg->driver->registration_status != NULL)
		netreg->driver->registration_status(netreg,
					init_registration_status, netreg);

	netreg->sim_watch = __ofono_modem_add_atom_watch(modem,
						OFONO_ATOM_TYPE_SIM,
						sim_watch, netreg, NULL);

	netreg->radio_online_watch = __ofono_modem_add_online_watch(modem,
					radio_online_watch_cb,
					netreg, NULL);

	__ofono_atom_register(netreg->atom, netreg_unregister);

	netreg->hfp_watch = __ofono_modem_add_atom_watch(modem,
					OFONO_ATOM_TYPE_EMULATOR_HFP,
					emulator_hfp_watch, netreg, NULL);

	netreg->signal_strength_data = g_new0(struct ofono_signal_strength, 1);
	if (netreg->signal_strength_data) {
		netreg->signal_strength_data->gw_signal_strength
			= g_new0(struct ofono_gw_signal_strength, 1);
		netreg->signal_strength_data->lte_signal_strength
			= g_new0(struct ofono_lte_signal_strength, 1);
	}

	netreg->oos_duration = 0;
	netreg->radio_status = RADIO_STATUS_UNKNOWN;
	netreg->report_oos_time_id = g_timeout_add(REPORTING_PERIOD,
				report_oos_duration, netreg);

	memset(&netreg->signal_level_start_time, 0,
	       sizeof(netreg->signal_level_start_time));
	netreg->current_signal_level = SIGNAL_STRENGTH_UNKNOWN;
	memset(netreg->signal_level_duration, 0, sizeof(netreg->signal_level_duration));
	netreg->signal_level_time_id = g_timeout_add(REPORTING_PERIOD,
			report_signal_level_info, netreg);

	memset(&netreg->rat_start_time, 0, sizeof(netreg->rat_start_time));
	netreg->current_rat = 0;
	memset(netreg->rat_duration, 0, sizeof(netreg->rat_duration));
	netreg->rat_report_time_id = g_timeout_add(REPORTING_PERIOD,
			report_rat_info, netreg);

}

void ofono_netreg_remove(struct ofono_netreg *netreg)
{
	__ofono_atom_free(netreg->atom);
}

void ofono_netreg_set_data(struct ofono_netreg *netreg, void *data)
{
	netreg->driver_data = data;
}

void *ofono_netreg_get_data(struct ofono_netreg *netreg)
{
	return netreg->driver_data;
}
