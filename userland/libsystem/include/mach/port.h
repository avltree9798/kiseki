/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Kiseki OS - Userland Mach port.h
 *
 * XNU-compatible Mach port types and constants.
 * Reference: osfmk/mach/port.h
 */

#ifndef _MACH_PORT_H_
#define _MACH_PORT_H_

/*
 * natural_t / integer_t - Machine-natural integer types
 *
 * On XNU these come from mach/machine/vm_types.h.
 * natural_t is always unsigned int (32-bit on both arm64 and x86_64).
 */
typedef unsigned int    natural_t;
typedef int             integer_t;

/* ============================================================================
 * Port Name Types
 * ============================================================================ */

typedef natural_t       mach_port_name_t;
typedef mach_port_name_t *mach_port_name_array_t;

/*
 * mach_port_t - User-space port name
 *
 * In XNU userland this goes through __darwin_mach_port_t but ultimately
 * resolves to natural_t (unsigned int).
 */
typedef natural_t       mach_port_t;
typedef mach_port_t     *mach_port_array_t;

/* ============================================================================
 * Port Right Types
 * ============================================================================ */

typedef natural_t       mach_port_right_t;

#define MACH_PORT_RIGHT_SEND            0
#define MACH_PORT_RIGHT_RECEIVE         1
#define MACH_PORT_RIGHT_SEND_ONCE       2
#define MACH_PORT_RIGHT_PORT_SET        3
#define MACH_PORT_RIGHT_DEAD_NAME       4
#define MACH_PORT_RIGHT_NUMBER          6

/* ============================================================================
 * Null and Dead Port Names
 * ============================================================================ */

#define MACH_PORT_NULL          0       /* Intentionally loose typing */
#define MACH_PORT_DEAD          ((mach_port_name_t) ~0)

#define MACH_PORT_VALID(name)   \
    (((name) != MACH_PORT_NULL) && ((name) != MACH_PORT_DEAD))

/* ============================================================================
 * Port Name Encoding (index + generation)
 * ============================================================================ */

#define MACH_PORT_INDEX(name)       ((name) >> 8)
#define MACH_PORT_GEN(name)         (((name) & 0xff) << 24)
#define MACH_PORT_MAKE(index, gen)  (((index) << 8) | ((gen) >> 24))

/* ============================================================================
 * Port Type (bitmask encoding of rights held)
 * ============================================================================ */

typedef natural_t       mach_port_type_t;
typedef mach_port_type_t *mach_port_type_array_t;

#define MACH_PORT_TYPE(right)   (1u << ((right) + 16))

#define MACH_PORT_TYPE_NONE         0
#define MACH_PORT_TYPE_SEND         MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND)
#define MACH_PORT_TYPE_RECEIVE      MACH_PORT_TYPE(MACH_PORT_RIGHT_RECEIVE)
#define MACH_PORT_TYPE_SEND_ONCE    MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND_ONCE)
#define MACH_PORT_TYPE_PORT_SET     MACH_PORT_TYPE(MACH_PORT_RIGHT_PORT_SET)
#define MACH_PORT_TYPE_DEAD_NAME    MACH_PORT_TYPE(MACH_PORT_RIGHT_DEAD_NAME)

/* Request notification bits */
#define MACH_PORT_TYPE_DNREQUEST            0x80000000u
#define MACH_PORT_TYPE_SPREQUEST            0x40000000u
#define MACH_PORT_TYPE_SPREQUEST_DELAYED    0x20000000u

/* Combinations */
#define MACH_PORT_TYPE_SEND_RECEIVE \
    (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE)
#define MACH_PORT_TYPE_SEND_RIGHTS  \
    (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE)
#define MACH_PORT_TYPE_PORT_RIGHTS  \
    (MACH_PORT_TYPE_SEND_RIGHTS | MACH_PORT_TYPE_RECEIVE)
#define MACH_PORT_TYPE_PORT_OR_DEAD \
    (MACH_PORT_TYPE_PORT_RIGHTS | MACH_PORT_TYPE_DEAD_NAME)
#define MACH_PORT_TYPE_ALL_RIGHTS   \
    (MACH_PORT_TYPE_PORT_OR_DEAD | MACH_PORT_TYPE_PORT_SET)

/* ============================================================================
 * Port Reference Counts
 * ============================================================================ */

typedef natural_t       mach_port_urefs_t;
typedef integer_t       mach_port_delta_t;
typedef natural_t       mach_port_seqno_t;
typedef natural_t       mach_port_mscount_t;
typedef natural_t       mach_port_msgcount_t;
typedef natural_t       mach_port_rights_t;
typedef unsigned int    mach_port_srights_t;

/* ============================================================================
 * Port Queue Limits
 * ============================================================================ */

#define MACH_PORT_QLIMIT_ZERO       0
#define MACH_PORT_QLIMIT_BASIC      5
#define MACH_PORT_QLIMIT_SMALL      16
#define MACH_PORT_QLIMIT_LARGE      1024
#define MACH_PORT_QLIMIT_KERNEL     65534
#define MACH_PORT_QLIMIT_DEFAULT    MACH_PORT_QLIMIT_BASIC
#define MACH_PORT_QLIMIT_MAX        MACH_PORT_QLIMIT_LARGE

/* ============================================================================
 * Port Limits Structure
 * ============================================================================ */

typedef struct mach_port_limits {
    mach_port_msgcount_t    mpl_qlimit;
} mach_port_limits_t;

/* ============================================================================
 * Port Status Structure
 * ============================================================================ */

typedef struct mach_port_status {
    mach_port_name_t    mps_pset;
    mach_port_seqno_t   mps_seqno;
    mach_port_mscount_t mps_mscount;
    mach_port_msgcount_t mps_qlimit;
    mach_port_msgcount_t mps_msgcount;
    mach_port_rights_t  mps_sorights;
    natural_t           mps_srights;
    natural_t           mps_pdrequest;
    natural_t           mps_nsrequest;
    natural_t           mps_flags;
} mach_port_status_t;

/* ============================================================================
 * Port Info Flavors
 * ============================================================================ */

typedef integer_t       *mach_port_info_t;
typedef int             mach_port_flavor_t;

#define MACH_PORT_LIMITS_INFO           1
#define MACH_PORT_RECEIVE_STATUS        2
#define MACH_PORT_DNREQUESTS_SIZE       3
#define MACH_PORT_TEMPOWNER             4
#define MACH_PORT_IMPORTANCE_RECEIVER   5
#define MACH_PORT_DENAP_RECEIVER        6
#define MACH_PORT_INFO_EXT              7
#define MACH_PORT_GUARD_INFO            8

/* ============================================================================
 * Legacy Compatibility
 * ============================================================================ */

typedef mach_port_t     port_t;
#define PORT_NULL       ((port_t) 0)

#endif /* _MACH_PORT_H_ */
