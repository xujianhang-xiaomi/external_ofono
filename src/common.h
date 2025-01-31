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

#include <glib.h>

#include <ofono/types.h>

/* 27.007 Section 7.3 <AcT> */
enum access_technology {
	ACCESS_TECHNOLOGY_GSM =			0,
	ACCESS_TECHNOLOGY_GSM_COMPACT =		1,
	ACCESS_TECHNOLOGY_UTRAN =		2,
	ACCESS_TECHNOLOGY_GSM_EGPRS =		3,
	ACCESS_TECHNOLOGY_UTRAN_HSDPA =		4,
	ACCESS_TECHNOLOGY_UTRAN_HSUPA =		5,
	ACCESS_TECHNOLOGY_UTRAN_HSDPA_HSUPA =	6,
	ACCESS_TECHNOLOGY_EUTRAN =		7,
	ACCESS_TECHNOLOGY_NB_IOT_M1 =		8,
	ACCESS_TECHNOLOGY_NB_IOT_NB1 =		9,
};

/*
 * 27.007 Section 7.2 <stat>
 * registration state as follows:
 * 1 - Registered, home network.
 * 2 - Not registered, but MT is currently searching a new operator to register.
 * 3 - Registration denied.
 * 4 - Unknown.
 * 5 - Registered, roaming.
 * 10 - Same as 0, but indicates that emergency calls are enabled.
 * 12 - Same as 2, but indicates that emergency calls are enabled.
 * 13 - Same as 3, but indicates that emergency calls are enabled.
 * 14 - Same as 4, but indicates that emergency calls are enabled.
 */
enum network_registration_status {
	NETWORK_REGISTRATION_STATUS_NOT_REGISTERED =		0,
	NETWORK_REGISTRATION_STATUS_REGISTERED =		1,
	NETWORK_REGISTRATION_STATUS_SEARCHING =			2,
	NETWORK_REGISTRATION_STATUS_DENIED =			3,
	NETWORK_REGISTRATION_STATUS_UNKNOWN =			4,
	NETWORK_REGISTRATION_STATUS_ROAMING =			5,
	NETWORK_REGISTRATION_STATUS_REGISTERED_SMS_EUTRAN =	6,
	NETWORK_REGISTRATION_STATUS_ROAMING_SMS_EUTRAN =	7,
	NETWORK_REGISTRATION_STATUS_REGISTED_EM =		8,
	NETWORK_REGISTRATION_STATUS_NOT_REGISTERED_EM =		10,
	NETWORK_REGISTRATION_STATUS_SEARCHING_EM =		12,
	NETWORK_REGISTRATION_STATUS_DENIED_EM =			13,
	NETWORK_REGISTRATION_STATUS_UNKNOWN_EM =		14,
};

/* 27.007 Section 7.3 <stat> */
enum operator_status {
	OPERATOR_STATUS_UNKNOWN =	0,
	OPERATOR_STATUS_AVAILABLE =	1,
	OPERATOR_STATUS_CURRENT =	2,
	OPERATOR_STATUS_FORBIDDEN =	3,
};

/* 27.007 Section 7.6 */
enum clip_validity {
	CLIP_VALIDITY_VALID =		0,
	CLIP_VALIDITY_WITHHELD =	1,
	CLIP_VALIDITY_NOT_AVAILABLE =	2,
};

/* 27.007 Section 7.29 */
enum packet_bearer {
	PACKET_BEARER_NONE =		0,
	PACKET_BEARER_GPRS =		1,
	PACKET_BEARER_EGPRS =		2,
	PACKET_BEARER_UMTS =		3,
	PACKET_BEARER_HSUPA =		4,
	PACKET_BEARER_HSDPA =		5,
	PACKET_BEARER_HSUPA_HSDPA =	6,
	PACKET_BEARER_EPS =		7,
};

/* 27.007 Section 7.30 */
enum cnap_validity {
	CNAP_VALIDITY_VALID =		0,
	CNAP_VALIDITY_WITHHELD =	1,
	CNAP_VALIDITY_NOT_AVAILABLE =	2,
};

/* 27.007 Section 7.18 */
enum call_status {
	CALL_STATUS_ACTIVE =		0,
	CALL_STATUS_HELD =		1,
	CALL_STATUS_DIALING =		2,
	CALL_STATUS_ALERTING =		3,
	CALL_STATUS_INCOMING =		4,
	CALL_STATUS_WAITING =		5,
	CALL_STATUS_DISCONNECTED
};

/* 27.007 Section 7.18 */
enum call_direction {
	CALL_DIRECTION_MOBILE_ORIGINATED =	0,
	CALL_DIRECTION_MOBILE_TERMINATED =	1,
};

/* 27.007 Section 7.11 */
enum bearer_class {
	BEARER_CLASS_VOICE =		1,
	BEARER_CLASS_DATA =		2,
	BEARER_CLASS_FAX =		4,
	BEARER_CLASS_DEFAULT =		7,
	BEARER_CLASS_SMS =		8,
	BEARER_CLASS_DATA_SYNC =	16,
	BEARER_CLASS_DATA_ASYNC =	32,
	/* According to 22.030, types 1-12 */
	BEARER_CLASS_SS_DEFAULT =	61,
	BEARER_CLASS_PACKET =		64,
	BEARER_CLASS_PAD =		128,
};

/* 22.030 Section 6.5.2 */
enum ss_control_type {
	SS_CONTROL_TYPE_ACTIVATION,
	SS_CONTROL_TYPE_DEACTIVATION,
	SS_CONTROL_TYPE_QUERY,
	SS_CONTROL_TYPE_REGISTRATION,
	SS_CONTROL_TYPE_ERASURE,
};

/* TS 27.007 Supplementary service notifications +CSSN */
enum ss_cssi {
	SS_MO_UNCONDITIONAL_FORWARDING =	0,
	SS_MO_CONDITIONAL_FORWARDING =		1,
	SS_MO_CALL_FORWARDED =			2,
	SS_MO_CALL_WAITING =			3,
	SS_MO_CUG_CALL =			4,
	SS_MO_OUTGOING_BARRING =		5,
	SS_MO_INCOMING_BARRING =		6,
	SS_MO_CLIR_SUPPRESSION_REJECTED	=	7,
	SS_MO_CALL_DEFLECTED =			8,
};

enum ss_cssu {
	SS_MT_CALL_FORWARDED =			0,
	SS_MT_CUG_CALL =			1,
	SS_MT_VOICECALL_ON_HOLD =		2,
	SS_MT_VOICECALL_RETRIEVED =		3,
	SS_MT_MULTIPARTY_VOICECALL =		4,
	SS_MT_VOICECALL_HOLD_RELEASED =		5,
	SS_MT_FORWARD_CHECK_SS_MESSAGE =	6,
	SS_MT_VOICECALL_IN_TRANSFER =		7,
	SS_MT_VOICECALL_TRANSFERRED =		8,
	SS_MT_CALL_DEFLECTED =			9,
	SS_MT_MULTIPARTY_VOICECALL_CANCELED =	10,
};

/* 27.007 Section 10.1.10 */
enum context_status {
	CONTEXT_STATUS_DEACTIVATED = 0,
	CONTEXT_STATUS_ACTIVATED = 1,
	CONTEXT_STATUS_DEACTIVATING = 2,
	CONTEXT_STATUS_ACTIVATING = 3,
	CONTEXT_STATUS_FAILED = 4,
	CONTEXT_STATUS_RETRYING = 5,
};

/**
 * The phone status.
 * IDLE : no phone activity
 * RINGING : a phone call is ringing or call waiting.
 * OFFHOOK : The phone is off hook. At least one call exists that is dialing,
 * active or holding and no calls are ringing or waiting.
 */
enum phone_status {
	PHONE_STATUS_IDLE = 0,
	PHONE_STATUS_RINGING = 1,
	PHONE_STATUS_OFFHOOK = 2,
};

enum radio_status {
	RADIO_STATUS_UNKNOWN = -1,
	RADIO_STATUS_UNAVAILABLE = 0,
	RADIO_STATUS_ON = 1,
	RADIO_STATUS_OFF = 2,
};

const char *abnormal_event_type_to_string(int type);
const char *reest_cause_to_string(unsigned int reest_cause);
const char *rach_fail_reason_to_string(unsigned int rach_fail_reason);
const char *oos_type_to_string(unsigned int oos_type);
const char *nas_timer_id_to_string(unsigned int timer_id);
const char *sip_srv_type_to_string(unsigned int srv_type);
const char *sip_method_to_string(unsigned int sip_method);
const char *rrc_timer_id_to_string(unsigned int timer_id);
const char *ecall_fail_cause_to_string(unsigned int cause);
const char *rtp_rtcp_error_to_string(unsigned int error_type);
const char *nas_procedure_type_to_string(unsigned int procedure_type);
const char *xcap_mode_to_string(unsigned int mode);
const char *xcap_reason_to_string(unsigned int reason);
const char *xcap_error_to_string(unsigned int error_type);
const char *call_end_reason_to_string(unsigned int reason);
const char *limited_cause_to_string(unsigned int cause);

const char *telephony_error_to_str(const struct ofono_error *error);

gboolean valid_number_format(const char *number, int length);
gboolean valid_phone_number_format(const char *number);
gboolean valid_long_phone_number_format(const char *number);
const char *phone_number_to_string(const struct ofono_phone_number *ph);
void parse_post_dial_string(const char *str, char *target, char *postdial);
void string_to_phone_number(const char *str, struct ofono_phone_number *ph, gboolean skip_plus);

gboolean valid_cdma_phone_number_format(const char *number);
const char *cdma_phone_number_to_string(
				const struct ofono_cdma_phone_number *ph);
void string_to_cdma_phone_number(const char *str,
				struct ofono_cdma_phone_number *ph);

int mmi_service_code_to_bearer_class(int code);

gboolean valid_ussd_string(const char *str, gboolean call_in_progress);
gboolean valid_actual_number_format(const char *number, int length);
gboolean parse_ss_control_string(char *str, int *ss_type,
					char **sc, char **sia,
					char **sib, char **sic,
					char **sid, char **dn);

const char *ss_control_type_to_string(enum ss_control_type type);

const char *bearer_class_to_string(enum bearer_class cls);

const char *registration_status_to_string(int status);
const char *registration_tech_to_string(int tech);
int registration_tech_from_string(const char *tech);
const char *packet_bearer_to_string(int bearer);

gboolean is_valid_apn(const char *apn);
const char *call_status_to_string(enum call_status status);

const char *gprs_proto_to_string(enum ofono_gprs_proto proto);
gboolean gprs_proto_from_string(const char *str, enum ofono_gprs_proto *proto);

const char *gprs_auth_method_to_string(enum ofono_gprs_auth_method auth);
gboolean gprs_auth_method_from_string(const char *str,
					enum ofono_gprs_auth_method *auth);

int in_range_or_unavailable(int value, int range_min, int range_max);
int get_rssi_dbm_from_asu(int rssi_asu);
int convert_rssnr_unit_from_ten_db_to_db(int rssnr);
int get_signal_level_from_rsrp(int rsrp);
int get_signal_level_from_rssi(int rssi);
gboolean is_gprs_context_type_support(const char *gc_type);