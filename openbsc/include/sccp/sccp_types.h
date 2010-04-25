/*
 * ITU Q.713 defined types for SCCP
 *
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef SCCP_TYPES_H
#define SCCP_TYPES_H

#include <endian.h>

/* Table 1/Q.713 - SCCP message types */
enum sccp_message_types {
	SCCP_MSG_TYPE_CR	= 1,
	SCCP_MSG_TYPE_CC	= 2,
	SCCP_MSG_TYPE_CREF	= 3,
	SCCP_MSG_TYPE_RLSD	= 4,
	SCCP_MSG_TYPE_RLC	= 5,
	SCCP_MSG_TYPE_DT1	= 6,
	SCCP_MSG_TYPE_DT2	= 7,
	SCCP_MSG_TYPE_AK	= 8,
	SCCP_MSG_TYPE_UDT	= 9,
	SCCP_MSG_TYPE_UDTS	= 10,
	SCCP_MSG_TYPE_ED	= 11,
	SCCP_MSG_TYPE_EA	= 12,
	SCCP_MSG_TYPE_RSR	= 13,
	SCCP_MSG_TYPE_RSC	= 14,
	SCCP_MSG_TYPE_ERR	= 15,
	SCCP_MSG_TYPE_IT	= 16,
	SCCP_MSG_TYPE_XUDT	= 17,
	SCCP_MSG_TYPE_XUDTS	= 18,
	SCCP_MSG_TYPE_LUDT	= 19,
	SCCP_MSG_TYPE_LUDTS	= 20
};

/* Table 2/Q.713 - SCCP parameter name codes */
enum sccp_parameter_name_codes {
	SCCP_PNC_END_OF_OPTIONAL		= 0,
	SCCP_PNC_DESTINATION_LOCAL_REFERENCE	= 1,
	SCCP_PNC_SOURCE_LOCAL_REFERENCE		= 2,
	SCCP_PNC_CALLED_PARTY_ADDRESS		= 3,
	SCCP_PNC_CALLING_PARTY_ADDRESS		= 4,
	SCCP_PNC_PROTOCOL_CLASS			= 5,
	SCCP_PNC_SEGMENTING			= 6,
	SCCP_PNC_RECEIVE_SEQ_NUMBER		= 7,
	SCCP_PNC_SEQUENCING			= 8,
	SCCP_PNC_CREDIT				= 9,
	SCCP_PNC_RELEASE_CAUSE			= 10,
	SCCP_PNC_RETURN_CAUSE			= 11,
	SCCP_PNC_RESET_CAUSE			= 12,
	SCCP_PNC_ERROR_CAUSE			= 13,
	SCCP_PNC_REFUSAL_CAUSE			= 14,
	SCCP_PNC_DATA				= 15,
	SCCP_PNC_SEGMENTATION			= 16,
	SCCP_PNC_HOP_COUNTER			= 17,
	SCCP_PNC_IMPORTANCE			= 18,
	SCCP_PNC_LONG_DATA			= 19,
};

/* Figure 3/Q.713 Called/calling party address */
enum {
	SCCP_TITLE_IND_NONE			= 0,
	SCCP_TITLE_IND_NATURE_ONLY		= 1,
	SCCP_TITLE_IND_TRANSLATION_ONLY		= 2,
	SCCP_TITLE_IND_TRANS_NUM_ENC		= 3,
	SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE	= 4,
};

enum {
	SCCP_CALL_ROUTE_ON_SSN			= 1,
	SCCP_CALL_ROUTE_ON_GT			= 0,
};

struct sccp_called_party_address {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t	point_code_indicator : 1,
			ssn_indicator	     : 1,
			global_title_indicator : 4,
			routing_indicator    : 1,
			reserved	     : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t	reserved	     : 1,
			routing_indicator    : 1,
			global_title_indicator : 4,
			ssn_indicator	     : 1,
			point_code_indicator : 1;
#endif
	u_int8_t	data[0];
} __attribute__((packed));

/* indicator indicates presence in the above order */

/* Figure 6/Q.713 */
struct sccp_signalling_point_code {
	u_int8_t	lsb;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t	msb : 6,
			reserved : 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t	reserved : 2,
			msb : 6;
#endif
} __attribute__((packed));

/* SSN == subsystem number */
enum sccp_subsystem_number {
	SCCP_SSN_NOT_KNOWN_OR_USED	    = 0,
	SCCP_SSN_MANAGEMENT		    = 1,
	SCCP_SSN_RESERVED_ITU		    = 2,
	SCCP_SSN_ISDN_USER_PART		    = 3,
	SCCP_SSN_OMAP			    = 4, /* operation, maint and administration part */
	SCCP_SSN_MAP			    = 5, /* mobile application part */
	SCCP_SSN_HLR			    = 6,
	SCCP_SSN_VLR			    = 7,
	SCCP_SSN_MSC			    = 8,
	SCCP_SSN_EIC			    = 9, /* equipent identifier centre */
	SCCP_SSN_AUC			    = 10, /* authentication centre */
	SCCP_SSN_ISDN_SUPPL_SERVICES	    = 11,
	SCCP_SSN_RESERVED_INTL		    = 12,
	SCCP_SSN_ISDN_EDGE_TO_EDGE	    = 13,
	SCCP_SSN_TC_TEST_RESPONDER	    = 14,

	/* From GSM 03.03 8.2 */
	SCCP_SSN_BSSAP			    = 254,
	SCCP_SSN_BSSOM			    = 253,
};

/* Q.713, 3.4.2.3 */
enum {
	SCCP_NAI_UNKNOWN		    = 0,
	SCCP_NAI_SUBSCRIBER_NUMBER	    = 1,
	SCCP_NAI_RESERVED_NATIONAL	    = 2,
	SCCP_NAI_NATIONAL_SIGNIFICANT	    = 3,
	SCCP_NAI_INTERNATIONAL		    = 4,
};

struct sccp_global_title {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t	nature_of_addr_ind : 7,
			odd_even : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t	odd_even : 1,
			nature_of_addr_ind : 7;
#endif
	u_int8_t	data[0];
} __attribute__((packed));

/* Q.713, 3.3 */
struct sccp_source_reference {
	u_int8_t    octet1;
	u_int8_t    octet2;
	u_int8_t    octet3;
} __attribute__((packed));

/* Q.714, 3.6 */
enum sccp_protocol_class {
	SCCP_PROTOCOL_CLASS_0		    = 0,
	SCCP_PROTOCOL_CLASS_1		    = 1,
	SCCP_PROTOCOL_CLASS_2		    = 2,
	SCCP_PROTOCOL_CLASS_3		    = 3,
};

/* bits 5-8 when class0, class1 is used */
enum sccp_protocol_options {
	SCCP_PROTOCOL_NO_SPECIAL	    = 0,
	SCCP_PROTOCOL_RETURN_MESSAGE	    = 8,
};

enum sccp_release_cause {
	SCCP_RELEASE_CAUSE_END_USER_ORIGINATED	    = 0,
	SCCP_RELEASE_CAUSE_END_USER_CONGESTION	    = 1,
	SCCP_RELEASE_CAUSE_END_USER_FAILURE	    = 2,
	SCCP_RELEASE_CAUSE_SCCP_USER_ORIGINATED	    = 3,
	SCCP_RELEASE_CAUSE_REMOTE_PROCEDURE_ERROR   = 4,
	SCCP_RELEASE_CAUSE_INCONSISTENT_CONN_DATA   = 5,
	SCCP_RELEASE_CAUSE_ACCESS_FAILURE	    = 6,
	SCCP_RELEASE_CAUSE_ACCESS_CONGESTION	    = 7,
	SCCP_RELEASE_CAUSE_SUBSYSTEM_FAILURE	    = 8,
	SCCP_RELEASE_CAUSE_SUBSYSTEM_CONGESTION	    = 9,
	SCCP_RELEASE_CAUSE_MTP_FAILURE		    = 10,
	SCCP_RELEASE_CAUSE_NETWORK_CONGESTION	    = 11,
	SCCP_RELEASE_CAUSE_EXPIRATION_RESET	    = 12,
	SCCP_RELEASE_CAUSE_EXPIRATION_INACTIVE	    = 13,
	SCCP_RELEASE_CAUSE_RESERVED		    = 14,
	SCCP_RELEASE_CAUSE_UNQUALIFIED		    = 15,
	SCCP_RELEASE_CAUSE_SCCP_FAILURE		    = 16,
};

enum sccp_return_cause {
	SCCP_RETURN_CAUSE_NO_TRANSLATION_NATURE	    = 0,
	SCCP_RETURN_CAUSE_NO_TRANSLATION	    = 1,
	SCCP_RETURN_CAUSE_SUBSYSTEM_CONGESTION	    = 2,
	SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE	    = 3,
	SCCP_RETURN_CAUSE_UNEQUIPPED_USER	    = 4,
	SCCP_RETURN_CAUSE_MTP_FAILURE		    = 5,
	SCCP_RETURN_CAUSE_NETWORK_CONGESTION	    = 6,
	SCCP_RETURN_CAUSE_UNQUALIFIED		    = 7,
	SCCP_RETURN_CAUSE_ERROR_IN_MSG_TRANSPORT    = 8,
	SCCP_RETURN_CAUSE_ERROR_IN_LOCAL_PROCESSING = 9,
	SCCP_RETURN_CAUSE_DEST_CANNOT_PERFORM_REASSEMBLY = 10,
	SCCP_RETURN_CAUSE_SCCP_FAILURE		    = 11,
	SCCP_RETURN_CAUSE_HOP_COUNTER_VIOLATION	    = 12,
	SCCP_RETURN_CAUSE_SEGMENTATION_NOT_SUPPORTED= 13,
	SCCP_RETURN_CAUSE_SEGMENTATION_FAOLURE	    = 14
};

enum sccp_reset_cause {
	SCCP_RESET_CAUSE_END_USER_ORIGINATED	    = 0,
	SCCP_RESET_CAUSE_SCCP_USER_ORIGINATED	    = 1,
	SCCP_RESET_CAUSE_MSG_OUT_OF_ORDER_PS	    = 2,
	SCCP_RESET_CAUSE_MSG_OUT_OF_ORDER_PR	    = 3,
	SCCP_RESET_CAUSE_RPC_OUT_OF_WINDOW	    = 4,
	SCCP_RESET_CAUSE_RPC_INCORRECT_PS	    = 5,
	SCCP_RESET_CAUSE_RPC_GENERAL		    = 6,
	SCCP_RESET_CAUSE_REMOTE_END_USER_OPERATIONAL= 7,
	SCCP_RESET_CAUSE_NETWORK_OPERATIONAL	    = 8,
	SCCP_RESET_CAUSE_ACCESS_OPERATIONAL	    = 9,
	SCCP_RESET_CAUSE_NETWORK_CONGESTION	    = 10,
	SCCP_RESET_CAUSE_RESERVED		    = 11,
};

enum sccp_error_cause {
	SCCP_ERROR_LRN_MISMATCH_UNASSIGNED	    = 0, /* local reference number */
	SCCP_ERROR_LRN_MISMATCH_INCONSISTENT	    = 1,
	SCCP_ERROR_POINT_CODE_MISMATCH		    = 2,
	SCCP_ERROR_SERVICE_CLASS_MISMATCH	    = 3,
	SCCP_ERROR_UNQUALIFIED			    = 4,
};

enum sccp_refusal_cause {
	SCCP_REFUSAL_END_USER_ORIGINATED	    = 0,
	SCCP_REFUSAL_END_USER_CONGESTION	    = 1,
	SCCP_REFUSAL_END_USER_FAILURE		    = 2,
	SCCP_REFUSAL_SCCP_USER_ORIGINATED	    = 3,
	SCCP_REFUSAL_DESTINATION_ADDRESS_UKNOWN	    = 4,
	SCCP_REFUSAL_DESTINATION_INACCESSIBLE	    = 5,
	SCCP_REFUSAL_NET_QOS_NON_TRANSIENT	    = 6,
	SCCP_REFUSAL_NET_QOS_TRANSIENT		    = 7,
	SCCP_REFUSAL_ACCESS_FAILURE		    = 8,
	SCCP_REFUSAL_ACCESS_CONGESTION		    = 9,
	SCCP_REFUSAL_SUBSYSTEM_FAILURE		    = 10,
	SCCP_REFUSAL_SUBSYTEM_CONGESTION	    = 11,
	SCCP_REFUSAL_EXPIRATION			    = 12,
	SCCP_REFUSAL_INCOMPATIBLE_USER_DATA	    = 13,
	SCCP_REFUSAL_RESERVED			    = 14,
	SCCP_REFUSAL_UNQUALIFIED		    = 15,
	SCCP_REFUSAL_HOP_COUNTER_VIOLATION	    = 16,
	SCCP_REFUSAL_SCCP_FAILURE		    = 17,
	SCCP_REFUSAL_UNEQUIPPED_USER		    = 18,
};

/*
 * messages... as of Q.713 Chapter 4
 */
struct sccp_connection_request {
	/* mandantory */
	u_int8_t			type;
	struct sccp_source_reference	source_local_reference;
	u_int8_t			proto_class;


	/* variable */
	u_int8_t			variable_called;
#if VARIABLE
	called_party_address
#endif

	/* optional */
	u_int8_t			optional_start;

#if OPTIONAL
	credit 3
	callingparty var 4-n
	data            3-130
	hop_counter     3
	importance      3
	end_of_optional 1
#endif

	u_int8_t			data[0];
} __attribute__((packed));

struct sccp_connection_confirm {
	/* mandantory */
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	struct sccp_source_reference	source_local_reference;
	u_int8_t			proto_class;

	/* optional */
	u_int8_t			optional_start;

	/* optional */
#if OPTIONAL
	credit 3
	called party 4
	data            3-130
	importance      3
	end_of_optional 1
#endif

	u_int8_t			data[0];
} __attribute__((packed));

struct sccp_connection_refused {
	/* mandantory */
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	u_int8_t			cause;

	/* optional */
	u_int8_t			optional_start;

	/* optional */
#if OPTIONAL
	called party 4
	data            3-130
	importance      3
	end_of_optional 1
#endif

	u_int8_t			data[0];
} __attribute__((packed));

struct sccp_connection_released {
	/* mandantory */
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	struct sccp_source_reference	source_local_reference;
	u_int8_t			release_cause;


	/* optional */
	u_int8_t			optional_start;

#if OPTIONAL
	data            3-130
	importance      3
	end_of_optional 1
#endif
	u_int8_t			data[0];
} __attribute__((packed));

struct sccp_connection_release_complete {
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	struct sccp_source_reference	source_local_reference;
} __attribute__((packed));

struct sccp_data_form1 {
	/* mandantory */
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	u_int8_t			segmenting;

	/* variable */
	u_int8_t			variable_start;

#if VARIABLE
	data 2-256;
#endif

	u_int8_t			data[0];
} __attribute__((packed));


struct sccp_data_unitdata {
	/* mandantory */
	u_int8_t			type;
	u_int8_t			proto_class;


	/* variable */
	u_int8_t			variable_called;
	u_int8_t			variable_calling;
	u_int8_t			variable_data;

#if VARIABLE
	called party address
	calling party address
#endif

	u_int8_t			data[0];
} __attribute__((packed));

struct sccp_data_it {
	/* mandantory */
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	struct sccp_source_reference	source_local_reference;
	u_int8_t			proto_class;

	u_int8_t			sequencing[2];
	u_int8_t			credit;
} __attribute__((packed));

struct sccp_proto_err {
	u_int8_t			type;
	struct sccp_source_reference	destination_local_reference;
	u_int8_t			error_cause;
};

#endif
