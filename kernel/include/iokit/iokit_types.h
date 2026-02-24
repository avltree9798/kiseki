/*
 * Kiseki OS - IOKit Fundamental Types
 *
 * Core type definitions for the IOKit framework. Mirrors XNU's
 * IOKit/IOTypes.h and IOKit/IOReturn.h.
 *
 * All IOReturn codes use the exact same numeric values as XNU so that
 * unmodified macOS binaries see correct error codes.
 *
 * Reference: XNU iokit/IOKit/IOTypes.h, iokit/IOKit/IOReturn.h
 */

#ifndef _IOKIT_IOKIT_TYPES_H
#define _IOKIT_IOKIT_TYPES_H

#include <kiseki/types.h>

/* ============================================================================
 * IOReturn - IOKit error/status codes
 *
 * XNU encodes IOReturn as:
 *   bits [31:26] = system (0x38 for IOKit)
 *   bits [25:14] = subsystem
 *   bits [13:0]  = code
 *
 * sys_iokit = err_system(0x38) = (0x38 << 26) = 0xE0000000
 * sub_iokit_common = err_sub(0) = 0
 *
 * Reference: XNU iokit/IOKit/IOReturn.h
 * ============================================================================ */

typedef kern_return_t   IOReturn;

/*
 * Mach error encoding macros (from mach/error.h).
 * We define them here so iokit_types.h is self-contained.
 */
#define err_system(x)           ((uint32_t)(((uint32_t)(x) & 0x3Fu) << 26))
#define err_sub(x)              ((uint32_t)(((uint32_t)(x) & 0xFFFu) << 14))

#define sys_iokit               err_system(0x38)
#define sub_iokit_common        err_sub(0)
#define sub_iokit_usb           err_sub(1)
#define sub_iokit_firewire      err_sub(2)
#define sub_iokit_block_storage err_sub(4)
#define sub_iokit_graphics      err_sub(5)
#define sub_iokit_networking    err_sub(6)

#define iokit_common_err(code)  (sys_iokit | sub_iokit_common | (code))
#define iokit_family_err(sub, code) (sys_iokit | (sub) | (code))

/* Core IOReturn values -- exact XNU numeric values */
#define kIOReturnSuccess         KERN_SUCCESS             /* 0x00000000 */
#define kIOReturnError           iokit_common_err(0x2bc)  /* 0xE00002BC */
#define kIOReturnNoMemory        iokit_common_err(0x2bd)  /* 0xE00002BD */
#define kIOReturnNoResources     iokit_common_err(0x2be)  /* 0xE00002BE */
#define kIOReturnIPCError        iokit_common_err(0x2bf)  /* 0xE00002BF */
#define kIOReturnNoDevice        iokit_common_err(0x2c0)  /* 0xE00002C0 */
#define kIOReturnNotPrivileged   iokit_common_err(0x2c1)  /* 0xE00002C1 */
#define kIOReturnBadArgument     iokit_common_err(0x2c2)  /* 0xE00002C2 */
#define kIOReturnLockedRead      iokit_common_err(0x2c3)  /* 0xE00002C3 */
#define kIOReturnLockedWrite     iokit_common_err(0x2c4)  /* 0xE00002C4 */
#define kIOReturnExclusiveAccess iokit_common_err(0x2c5)  /* 0xE00002C5 */
#define kIOReturnBadMessageID    iokit_common_err(0x2c6)  /* 0xE00002C6 */
#define kIOReturnUnsupported     iokit_common_err(0x2c7)  /* 0xE00002C7 */
#define kIOReturnVMError         iokit_common_err(0x2c8)  /* 0xE00002C8 */
#define kIOReturnInternalError   iokit_common_err(0x2c9)  /* 0xE00002C9 */
#define kIOReturnIOError         iokit_common_err(0x2ca)  /* 0xE00002CA */
#define kIOReturnCannotLock      iokit_common_err(0x2cc)  /* 0xE00002CC */
#define kIOReturnNotOpen         iokit_common_err(0x2cd)  /* 0xE00002CD */
#define kIOReturnNotReadable     iokit_common_err(0x2ce)  /* 0xE00002CE */
#define kIOReturnNotWritable     iokit_common_err(0x2cf)  /* 0xE00002CF */
#define kIOReturnNotAligned      iokit_common_err(0x2d0)  /* 0xE00002D0 */
#define kIOReturnBadMedia        iokit_common_err(0x2d1)  /* 0xE00002D1 */
#define kIOReturnStillOpen       iokit_common_err(0x2d2)  /* 0xE00002D2 */
#define kIOReturnRLDError        iokit_common_err(0x2d3)  /* 0xE00002D3 */
#define kIOReturnDMAError        iokit_common_err(0x2d4)  /* 0xE00002D4 */
#define kIOReturnBusy            iokit_common_err(0x2d5)  /* 0xE00002D5 */
#define kIOReturnTimeout         iokit_common_err(0x2d6)  /* 0xE00002D6 */
#define kIOReturnOffline         iokit_common_err(0x2d7)  /* 0xE00002D7 */
#define kIOReturnNotReady        iokit_common_err(0x2d8)  /* 0xE00002D8 */
#define kIOReturnNotAttached     iokit_common_err(0x2d9)  /* 0xE00002D9 */
#define kIOReturnNoChannels      iokit_common_err(0x2da)  /* 0xE00002DA */
#define kIOReturnNoSpace         iokit_common_err(0x2db)  /* 0xE00002DB */
#define kIOReturnPortExists      iokit_common_err(0x2dd)  /* 0xE00002DD */
#define kIOReturnCannotWire      iokit_common_err(0x2de)  /* 0xE00002DE */
#define kIOReturnNoInterrupt     iokit_common_err(0x2df)  /* 0xE00002DF */
#define kIOReturnNoFrames        iokit_common_err(0x2e0)  /* 0xE00002E0 */
#define kIOReturnMessageTooLarge iokit_common_err(0x2e1)  /* 0xE00002E1 */
#define kIOReturnNotPermitted    iokit_common_err(0x2e2)  /* 0xE00002E2 */
#define kIOReturnNoPower         iokit_common_err(0x2e3)  /* 0xE00002E3 */
#define kIOReturnNoMedia         iokit_common_err(0x2e4)  /* 0xE00002E4 */
#define kIOReturnUnformattedMedia iokit_common_err(0x2e5) /* 0xE00002E5 */
#define kIOReturnUnsupportedMode iokit_common_err(0x2e6)  /* 0xE00002E6 */
#define kIOReturnUnderrun        iokit_common_err(0x2e7)  /* 0xE00002E7 */
#define kIOReturnOverrun         iokit_common_err(0x2e8)  /* 0xE00002E8 */
#define kIOReturnDeviceError     iokit_common_err(0x2e9)  /* 0xE00002E9 */
#define kIOReturnNoCompletion    iokit_common_err(0x2ea)  /* 0xE00002EA */
#define kIOReturnAborted         iokit_common_err(0x2eb)  /* 0xE00002EB */
#define kIOReturnNoBandwidth     iokit_common_err(0x2ec)  /* 0xE00002EC */
#define kIOReturnNotResponding   iokit_common_err(0x2ed)  /* 0xE00002ED */
#define kIOReturnIsoTooOld       iokit_common_err(0x2ee)  /* 0xE00002EE */
#define kIOReturnIsoTooNew       iokit_common_err(0x2ef)  /* 0xE00002EF */
#define kIOReturnNotFound        iokit_common_err(0x2f0)  /* 0xE00002F0 */
#define kIOReturnInvalid         iokit_common_err(0x1)    /* 0xE0000001 */

/* ============================================================================
 * IOKit Scalar Types
 *
 * Reference: XNU iokit/IOKit/IOTypes.h
 * ============================================================================ */

typedef uint32_t        IOOptionBits;
typedef int32_t         IOFixed;
typedef uint32_t        IOVersion;
typedef uint32_t        IOItemCount;
typedef uint32_t        IOCacheMode;

typedef uint32_t        IOByteCount32;
typedef uint64_t        IOByteCount64;
typedef uint64_t        IOByteCount;        /* 64-bit on arm64 */

typedef uint32_t        IOPhysicalAddress32;
typedef uint64_t        IOPhysicalAddress64;
typedef uint32_t        IOPhysicalLength32;
typedef uint64_t        IOPhysicalLength64;

typedef uint64_t        IOPhysicalAddress;  /* 64-bit on arm64 */
typedef uint64_t        IOPhysicalLength;   /* 64-bit on arm64 */
typedef uint64_t        IOVirtualAddress;

typedef struct {
    IOPhysicalAddress   address;
    IOByteCount         length;
} IOPhysicalRange;

typedef struct {
    IOVirtualAddress    address;
    IOByteCount         length;
} IOVirtualRange;

typedef IOVirtualRange  IOAddressRange;     /* arm64 layout */

/* ============================================================================
 * IODirection - DMA/transfer direction
 *
 * Reference: XNU iokit/IOKit/IOMemoryDescriptor.h
 * ============================================================================ */

typedef uint32_t        IODirection;

#define kIODirectionNone    0x0
#define kIODirectionIn      0x1     /* Device -> memory (read from device) */
#define kIODirectionOut     0x2     /* Memory -> device (write to device) */
#define kIODirectionInOut   (kIODirectionIn | kIODirectionOut)

/* ============================================================================
 * IOMemoryMap cache modes
 *
 * Reference: XNU iokit/IOKit/IOTypes.h (kIOMapInhibitCache, etc.)
 * ============================================================================ */

#define kIOMapAnywhere          0x00000001
#define kIOMapInhibitCache      0x00000100
#define kIOMapWriteThruCache    0x00000200
#define kIOMapCopybackCache     0x00000400
#define kIOMapWriteCombineCache 0x00000800
#define kIOMapDefaultCache      0x00000000

/* ============================================================================
 * IOKit Object Types (userland-visible as mach_port_t)
 *
 * In-kernel, IOKit objects are C structs. When exposed to userland
 * via Mach IPC, they become mach_port_t handles.
 *
 * Reference: XNU iokit/IOKit/IOTypes.h
 * ============================================================================ */

#define IO_OBJECT_NULL          ((uint32_t)0)

/* Scale factors (XNU compatibility) */
#define kNanosecondScale        1
#define kMicrosecondScale       1000
#define kMillisecondScale       (1000 * 1000)
#define kSecondScale            (1000 * 1000 * 1000)
#define kTickScale              (kSecondScale / 100)

/* ============================================================================
 * IOKit Registry Plane Names
 *
 * Reference: XNU iokit/IOKit/IORegistryEntry.h
 * ============================================================================ */

#define kIOServicePlane         "IOService"
#define kIODeviceTreePlane      "IODeviceTree"
#define kIOPowerPlane           "IOPower"

/* ============================================================================
 * IOKit Matching Keys
 *
 * Reference: XNU iokit/IOKit/IOKitKeys.h
 * ============================================================================ */

#define kIOProviderClassKey         "IOProviderClass"
#define kIOClassKey                 "IOClass"
#define kIONameMatchKey             "IONameMatch"
#define kIOPropertyMatchKey         "IOPropertyMatch"
#define kIOProbeScoreKey            "IOProbeScore"
#define kIOMatchCategoryKey         "IOMatchCategory"
#define kIOResourceMatchKey         "IOResourceMatch"
#define kIOBSDNameKey               "BSD Name"
#define kIOBSDMajorKey              "BSD Major"
#define kIOBSDMinorKey              "BSD Minor"

/* ============================================================================
 * IOKit Service State Bits
 *
 * Reference: XNU iokit/IOKit/IOService.h
 * ============================================================================ */

#define kIOServiceRegisteredState       0x00000001
#define kIOServiceMatchedState          0x00000002
#define kIOServiceInactiveState         0x00000004
#define kIOServiceBusyStateMask         0xFF000000
#define kIOServiceBusyStateShift        24

/* ============================================================================
 * IOKit Notification Types
 *
 * Reference: XNU iokit/IOKit/IOKitKeys.h
 * ============================================================================ */

#define kIOPublishNotification          "IOServicePublish"
#define kIOFirstPublishNotification     "IOServiceFirstPublish"
#define kIOMatchedNotification          "IOServiceMatched"
#define kIOFirstMatchNotification       "IOServiceFirstMatch"
#define kIOTerminatedNotification       "IOServiceTerminate"

/* ============================================================================
 * IOKit Mach Message IDs
 *
 * Userland IOKit framework sends Mach messages to IOKit object ports.
 * The msgh_id field identifies the operation. These must match what
 * IOKitLib.c uses in MIG-generated stubs.
 *
 * Reference: XNU osfmk/device/device.defs, iokit/IOKit/IOKitServer.h
 * ============================================================================ */

/*
 * MIG routine IDs, counted from subsystem base 2800 in device.defs.
 *
 * Each `routine` and `skip` in device.defs increments the ID by 1.
 * We use the modern 64-bit variants where available (e.g.
 * io_connect_map_memory_into_task instead of io_connect_map_memory).
 *
 * Reference: XNU osfmk/device/device.defs (subsystem iokit 2800)
 */
#define IOKIT_MSG_BASE                      2800

/* 2804 = io_service_get_matching_services (plural) */
#define kIOServiceGetMatchingServicesMsg     (IOKIT_MSG_BASE + 4)   /* 2804 */

/* 2812 = io_registry_entry_get_property_bytes */
#define kIORegistryEntryGetPropertyMsg       (IOKIT_MSG_BASE + 12)  /* 2812 */

/* 2816 = io_service_close */
#define kIOServiceCloseMsg                   (IOKIT_MSG_BASE + 16)  /* 2816 */

/* 2828 = io_registry_entry_set_properties */
#define kIORegistryEntrySetPropertyMsg       (IOKIT_MSG_BASE + 28)  /* 2828 */

/* 2862 = io_service_open_extended */
#define kIOServiceOpenMsg                    (IOKIT_MSG_BASE + 62)  /* 2862 */

/* 2863 = io_connect_map_memory_into_task */
#define kIOConnectMapMemoryMsg               (IOKIT_MSG_BASE + 63)  /* 2863 */

/* 2864 = io_connect_unmap_memory_from_task */
#define kIOConnectUnmapMemoryMsg             (IOKIT_MSG_BASE + 64)  /* 2864 */

/* 2865 = io_connect_method */
#define kIOConnectCallMethodMsg              (IOKIT_MSG_BASE + 65)  /* 2865 */

/* 2873 = io_service_get_matching_service (singular) */
#define kIOServiceGetMatchingServiceMsg      (IOKIT_MSG_BASE + 73)  /* 2873 */

/* ============================================================================
 * IOKit Kobject Types
 *
 * Used in struct ipc_port to identify what kind of IOKit object a
 * port represents. Stored in ipc_port.kobject_type.
 *
 * Reference: XNU osfmk/ipc/ipc_kobject.h
 * ============================================================================ */

#define IKOT_NONE               0
#define IKOT_IOKIT_OBJECT       29      /* Generic IOKit object */
#define IKOT_IOKIT_CONNECT      30      /* IOUserClient connection */
#define IKOT_IOKIT_IDENT        31      /* IOKit identification token */
#define IKOT_MASTER_DEVICE      32      /* IOKit master port */

/* ============================================================================
 * IOExternalMethod / IOExternalMethodArguments
 *
 * Describes the dispatch table entry for an IOUserClient external method.
 *
 * Reference: XNU iokit/IOKit/IOUserClient.h
 * ============================================================================ */

/* Maximum number of scalar input/output values */
#define kIOExternalMethodScalarInputMax     16
#define kIOExternalMethodScalarOutputMax    16

/* Maximum structure input/output size */
#define kIOExternalMethodStructureInputMax  4096
#define kIOExternalMethodStructureOutputMax 4096

/* ============================================================================
 * Forward Declarations
 *
 * All IOKit C struct types used across the framework.
 * ============================================================================ */

struct io_object;
struct io_registry_entry;
struct io_service;
struct io_user_client;
struct io_memory_descriptor;
struct io_memory_map;
struct io_work_loop;
struct io_event_source;
struct io_interrupt_event_source;
struct io_command_gate;
struct io_registry;
struct io_prop_table;

#endif /* _IOKIT_IOKIT_TYPES_H */
