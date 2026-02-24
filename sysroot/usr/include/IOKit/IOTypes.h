/*
 * Kiseki OS - IOKit Fundamental Types
 *
 * Core type definitions for the IOKit framework, matching XNU's
 * IOKit/IOTypes.h. Provides scalar types, direction flags, memory
 * map cache modes, and object null constants.
 *
 * Reference: XNU iokit/IOKit/IOTypes.h
 */

#ifndef _IOKIT_IOTYPES_H
#define _IOKIT_IOTYPES_H

#include <mach/port.h>
#include <mach/kern_return.h>
#include <IOKit/IOReturn.h>

/* ============================================================================
 * IOKit Scalar Types
 * ============================================================================ */

typedef unsigned int    IOOptionBits;
typedef int             IOFixed;
typedef unsigned int    IOVersion;
typedef unsigned int    IOItemCount;
typedef unsigned int    IOCacheMode;

typedef unsigned int    IOByteCount32;
typedef unsigned long   IOByteCount64;
typedef unsigned long   IOByteCount;        /* 64-bit on arm64 */

typedef unsigned int    IOPhysicalAddress32;
typedef unsigned long   IOPhysicalAddress64;
typedef unsigned int    IOPhysicalLength32;
typedef unsigned long   IOPhysicalLength64;

typedef unsigned long   IOPhysicalAddress;  /* 64-bit on arm64 */
typedef unsigned long   IOPhysicalLength;   /* 64-bit on arm64 */
typedef unsigned long   IOVirtualAddress;

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
 * IOKit Object Types (userland Mach port handles)
 * ============================================================================ */

typedef mach_port_t     io_object_t;
typedef io_object_t     io_connect_t;
typedef io_object_t     io_iterator_t;
typedef io_object_t     io_registry_entry_t;
typedef io_object_t     io_service_t;

#define IO_OBJECT_NULL  ((io_object_t) 0)

/* ============================================================================
 * IODirection - DMA/transfer direction
 *
 * Reference: XNU iokit/IOKit/IOMemoryDescriptor.h
 * ============================================================================ */

typedef unsigned int    IODirection;

#define kIODirectionNone    0x0
#define kIODirectionIn      0x1     /* Device -> memory (read from device) */
#define kIODirectionOut     0x2     /* Memory -> device (write to device) */
#define kIODirectionInOut   (kIODirectionIn | kIODirectionOut)

/* ============================================================================
 * IOMemoryMap cache modes
 *
 * Reference: XNU iokit/IOKit/IOTypes.h
 * ============================================================================ */

#define kIOMapAnywhere          0x00000001
#define kIOMapInhibitCache      0x00000100
#define kIOMapWriteThruCache    0x00000200
#define kIOMapCopybackCache     0x00000400
#define kIOMapWriteCombineCache 0x00000800
#define kIOMapDefaultCache      0x00000000

/* ============================================================================
 * Scale factors (XNU compatibility)
 * ============================================================================ */

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

#endif /* _IOKIT_IOTYPES_H */
