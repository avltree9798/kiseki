/*
 * Kiseki OS - IOKit IOReturn Codes
 *
 * IOKit error/status codes matching XNU's exact numeric values.
 * Unmodified macOS binaries see the same error codes.
 *
 * Reference: XNU iokit/IOKit/IOReturn.h
 */

#ifndef _IOKIT_IORETURN_H
#define _IOKIT_IORETURN_H

#include <mach/kern_return.h>

typedef kern_return_t   IOReturn;

/*
 * Mach error encoding macros (from mach/error.h).
 * Guard against redefinition when building with macOS SDK headers.
 */
#ifndef err_system
#define err_system(x)           ((unsigned int)(((unsigned int)(x) & 0x3Fu) << 26))
#endif
#ifndef err_sub
#define err_sub(x)              ((unsigned int)(((unsigned int)(x) & 0xFFFu) << 14))
#endif

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

#endif /* _IOKIT_IORETURN_H */
