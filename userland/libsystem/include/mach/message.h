/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Kiseki OS - Userland Mach message.h
 *
 * XNU-compatible Mach message types, constants, and structures.
 * Reference: osfmk/mach/message.h
 */

#ifndef _MACH_MESSAGE_H_
#define _MACH_MESSAGE_H_

#include <mach/port.h>
#include <mach/kern_return.h>

/* ============================================================================
 * Message Types
 * ============================================================================ */

typedef unsigned int    mach_msg_bits_t;
typedef natural_t       mach_msg_size_t;
typedef integer_t       mach_msg_id_t;
typedef unsigned int    mach_msg_priority_t;
typedef natural_t       mach_msg_timeout_t;
typedef unsigned int    mach_msg_type_name_t;
typedef unsigned int    mach_msg_copy_options_t;
typedef unsigned int    mach_msg_descriptor_type_t;
typedef unsigned int    mach_msg_trailer_type_t;
typedef unsigned int    mach_msg_trailer_size_t;

/*
 * mach_msg_return_t - Return type for mach_msg()
 * On XNU this is kern_return_t.
 */
typedef kern_return_t   mach_msg_return_t;

/*
 * mach_msg_option_t / mach_msg_options_t
 * On XNU these are integer_t.
 */
typedef integer_t       mach_msg_option_t;
typedef integer_t       mach_msg_options_t;

/* Natural_t subtypes for message info */
typedef natural_t       mach_msg_type_size_t;
typedef natural_t       mach_msg_type_number_t;

/* ============================================================================
 * Message Header Bits Encoding
 *
 * msgh_bits layout:
 *   bits [4:0]   = remote port disposition
 *   bits [12:8]  = local port disposition
 *   bits [20:16] = voucher port disposition
 *   bit  [31]    = MACH_MSGH_BITS_COMPLEX
 * ============================================================================ */

#define MACH_MSGH_BITS_ZERO             0x00000000u

#define MACH_MSGH_BITS_REMOTE_MASK      0x0000001fu
#define MACH_MSGH_BITS_LOCAL_MASK       0x00001f00u
#define MACH_MSGH_BITS_VOUCHER_MASK     0x001f0000u

#define MACH_MSGH_BITS_PORTS_MASK       \
    (MACH_MSGH_BITS_REMOTE_MASK | MACH_MSGH_BITS_LOCAL_MASK | \
     MACH_MSGH_BITS_VOUCHER_MASK)

#define MACH_MSGH_BITS_COMPLEX          0x80000000u

/* Used in older variants and our kernel — accept both bit widths */
#define MACH_MSGH_BITS_REMOTE_MASK_COMPAT   0x000000FFu
#define MACH_MSGH_BITS_LOCAL_MASK_COMPAT    0x0000FF00u

#define MACH_MSGH_BITS(remote, local) \
    ((mach_msg_bits_t)((remote) | ((local) << 8)))

#define MACH_MSGH_BITS_SET_PORTS(remote, local, voucher) \
    ((mach_msg_bits_t)((remote) | ((local) << 8) | ((voucher) << 16)))

#define MACH_MSGH_BITS_REMOTE(bits) \
    ((mach_msg_type_name_t)((bits) & MACH_MSGH_BITS_REMOTE_MASK))

#define MACH_MSGH_BITS_LOCAL(bits) \
    ((mach_msg_type_name_t)(((bits) & MACH_MSGH_BITS_LOCAL_MASK) >> 8))

#define MACH_MSGH_BITS_VOUCHER(bits) \
    ((mach_msg_type_name_t)(((bits) & MACH_MSGH_BITS_VOUCHER_MASK) >> 16))

/* ============================================================================
 * Message Type Names (disposition of port rights in header)
 * ============================================================================ */

#define MACH_MSG_TYPE_MOVE_RECEIVE      16
#define MACH_MSG_TYPE_MOVE_SEND         17
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18
#define MACH_MSG_TYPE_COPY_SEND         19
#define MACH_MSG_TYPE_MAKE_SEND         20
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21
#define MACH_MSG_TYPE_COPY_RECEIVE      22
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24
#define MACH_MSG_TYPE_DISPOSE_SEND      25
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26

/* Legacy alias */
#define MACH_MSG_TYPE_PORT_SEND         MACH_MSG_TYPE_MOVE_SEND

/* ============================================================================
 * Message Copy Options
 * ============================================================================ */

#define MACH_MSG_PHYSICAL_COPY          0
#define MACH_MSG_VIRTUAL_COPY           1
#define MACH_MSG_ALLOCATE               2

/* ============================================================================
 * Message Header Structure
 * ============================================================================ */

typedef struct {
    mach_msg_bits_t     msgh_bits;
    mach_msg_size_t     msgh_size;
    mach_port_t         msgh_remote_port;
    mach_port_t         msgh_local_port;
    mach_port_name_t    msgh_voucher_port;
    mach_msg_id_t       msgh_id;
} mach_msg_header_t;

/* Alias for compatibility - voucher_port field is sometimes called reserved */
#define msgh_reserved   msgh_voucher_port

#define MACH_MSG_NULL   ((mach_msg_header_t *) 0)

/* ============================================================================
 * Message Body (for complex messages with descriptors)
 * ============================================================================ */

typedef struct {
    mach_msg_size_t     msgh_descriptor_count;
} mach_msg_body_t;

typedef struct {
    mach_msg_header_t   header;
    mach_msg_body_t     body;
} mach_msg_base_t;

/* ============================================================================
 * Message Descriptors (complex message inline port/OOL descriptors)
 * ============================================================================ */

#define MACH_MSG_PORT_DESCRIPTOR            0
#define MACH_MSG_OOL_DESCRIPTOR             1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR       2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR    3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR    4

typedef struct {
    mach_port_t             name;
    mach_msg_size_t         pad1;
    unsigned int            pad2 : 16;
    mach_msg_type_name_t    disposition : 8;
    mach_msg_descriptor_type_t type : 8;
} mach_msg_port_descriptor_t;

typedef struct {
    void                    *address;
    unsigned int            deallocate : 8;
    mach_msg_copy_options_t copy : 8;
    unsigned int            pad1 : 8;
    mach_msg_descriptor_type_t type : 8;
    mach_msg_size_t         size;
} mach_msg_ool_descriptor_t;

/* ============================================================================
 * Message Trailer
 * ============================================================================ */

#define MACH_MSG_TRAILER_FORMAT_0       0

typedef struct {
    mach_msg_trailer_type_t     msgh_trailer_type;
    mach_msg_trailer_size_t     msgh_trailer_size;
} mach_msg_trailer_t;

#define MACH_MSG_TRAILER_MINIMUM_SIZE   sizeof(mach_msg_trailer_t)

/* Security token (for audit trailers) */
typedef struct {
    unsigned int val[2];
} security_token_t;

typedef struct {
    unsigned int val[8];
} audit_token_t;

/* Extended trailers */
typedef struct {
    mach_msg_trailer_type_t     msgh_trailer_type;
    mach_msg_trailer_size_t     msgh_trailer_size;
    mach_port_seqno_t           msgh_seqno;
} mach_msg_seqno_trailer_t;

typedef struct {
    mach_msg_trailer_type_t     msgh_trailer_type;
    mach_msg_trailer_size_t     msgh_trailer_size;
    mach_port_seqno_t           msgh_seqno;
    security_token_t            msgh_sender;
} mach_msg_security_trailer_t;

typedef struct {
    mach_msg_trailer_type_t     msgh_trailer_type;
    mach_msg_trailer_size_t     msgh_trailer_size;
    mach_port_seqno_t           msgh_seqno;
    security_token_t            msgh_sender;
    audit_token_t               msgh_audit;
} mach_msg_audit_trailer_t;

/* Maximum trailer is the audit trailer */
typedef mach_msg_audit_trailer_t mach_msg_max_trailer_t;

/* Trailer type request values */
#define MACH_RCV_TRAILER_NULL       0
#define MACH_RCV_TRAILER_SEQNO      1
#define MACH_RCV_TRAILER_SENDER     2
#define MACH_RCV_TRAILER_AUDIT      3
#define MACH_RCV_TRAILER_CTX        4

/* ============================================================================
 * Message Options (for mach_msg() option parameter)
 * ============================================================================ */

#define MACH_MSG_OPTION_NONE        0x00000000

#define MACH_SEND_MSG               0x00000001
#define MACH_RCV_MSG                0x00000002
#define MACH_RCV_LARGE              0x00000004

#define MACH_SEND_TIMEOUT           0x00000010
#define MACH_SEND_INTERRUPT         0x00000040

#define MACH_RCV_TIMEOUT            0x00000100
#define MACH_RCV_INTERRUPT          0x00000400
#define MACH_RCV_VOUCHER            0x00000800

/* ============================================================================
 * Message Return Codes
 * ============================================================================ */

#define MACH_MSG_SUCCESS                0x00000000

/* Send errors */
#define MACH_SEND_IN_PROGRESS           0x10000001
#define MACH_SEND_INVALID_DATA          0x10000002
#define MACH_SEND_INVALID_DEST          0x10000003
#define MACH_SEND_TIMED_OUT             0x10000004
#define MACH_SEND_INVALID_VOUCHER       0x10000005
#define MACH_SEND_INTERRUPTED           0x10000007
#define MACH_SEND_MSG_TOO_SMALL         0x10000008
#define MACH_SEND_INVALID_REPLY         0x10000009
#define MACH_SEND_INVALID_RIGHT         0x1000000a
#define MACH_SEND_INVALID_NOTIFY        0x1000000b
#define MACH_SEND_INVALID_MEMORY        0x1000000c
#define MACH_SEND_NO_BUFFER             0x1000000d
#define MACH_SEND_TOO_LARGE             0x1000000e
#define MACH_SEND_INVALID_TYPE          0x1000000f
#define MACH_SEND_INVALID_HEADER        0x10000010
#define MACH_SEND_INVALID_TRAILER       0x10000011
#define MACH_SEND_INVALID_RT_OOL_SIZE   0x10000015

/* Receive errors */
#define MACH_RCV_IN_PROGRESS            0x10004001
#define MACH_RCV_INVALID_NAME           0x10004002
#define MACH_RCV_TIMED_OUT              0x10004003
#define MACH_RCV_TOO_LARGE              0x10004004
#define MACH_RCV_INTERRUPTED            0x10004005
#define MACH_RCV_PORT_CHANGED           0x10004006
#define MACH_RCV_INVALID_NOTIFY         0x10004007
#define MACH_RCV_INVALID_DATA           0x10004008
#define MACH_RCV_PORT_DIED              0x10004009
#define MACH_RCV_IN_SET                 0x1000400a
#define MACH_RCV_HEADER_ERROR           0x1000400b
#define MACH_RCV_BODY_ERROR             0x1000400c
#define MACH_RCV_INVALID_TYPE           0x1000400d
#define MACH_RCV_SCATTER_SMALL          0x1000400e
#define MACH_RCV_INVALID_TRAILER        0x1000400f

/* ============================================================================
 * Message Size
 * ============================================================================ */

#define MACH_MSG_SIZE_MAX       ((mach_msg_size_t) ~0)
#define MACH_MSG_TIMEOUT_NONE   ((mach_msg_timeout_t) 0)

/* ============================================================================
 * Empty Messages (for simple send/receive patterns)
 * ============================================================================ */

typedef struct {
    mach_msg_header_t       header;
} mach_msg_empty_send_t;

typedef struct {
    mach_msg_header_t       header;
    mach_msg_trailer_t      trailer;
} mach_msg_empty_rcv_t;

typedef union {
    mach_msg_empty_send_t   send;
    mach_msg_empty_rcv_t    rcv;
} mach_msg_empty_t;

/* ============================================================================
 * mach_msg() - Primary Mach IPC function
 *
 * This is the userland entry point. It invokes the mach_msg_trap
 * (Mach trap -31) to send and/or receive messages.
 * ============================================================================ */

extern mach_msg_return_t mach_msg(
    mach_msg_header_t   *msg,
    mach_msg_option_t   option,
    mach_msg_size_t     send_size,
    mach_msg_size_t     rcv_size,
    mach_port_name_t    rcv_name,
    mach_msg_timeout_t  timeout,
    mach_port_name_t    notify);

#endif /* _MACH_MESSAGE_H_ */
