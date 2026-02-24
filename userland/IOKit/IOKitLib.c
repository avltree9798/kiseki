/*
 * Kiseki OS - IOKit.framework Client Library
 *
 * Freestanding implementation of the IOKit userland client library.
 * On macOS, this is IOKit.framework (built from IOKitUser/IOKitLib.c),
 * which provides the API for userland programs to communicate with IOKit
 * kernel drivers via Mach IPC.
 *
 * This file is completely freestanding — it does NOT #include any
 * headers. All types are defined inline. Exported function signatures
 * use void* for struct pointer parameters; the public headers in
 * IOKit/IOKitLib.h declare the properly-typed versions.
 *
 * Functions imported from libSystem.B.dylib (via dynamic linking):
 *   mach_msg(), mach_reply_port(), mach_task_self(),
 *   mach_port_deallocate(), bootstrap_look_up()
 *
 * Wire format: All messages must exactly match the structures defined
 * in kernel/iokit/iokit_mach.c.
 *
 * Reference: apple-oss-distributions/IOKitUser/IOKitLib.c
 */

/* ============================================================================
 * Visibility
 * ============================================================================ */

#define EXPORT  __attribute__((visibility("default")))
#define HIDDEN  __attribute__((visibility("hidden")))

/* ============================================================================
 * Imported Functions from libSystem.B.dylib
 *
 * These are resolved at runtime by dyld. We declare them extern here
 * with the exact signatures that libSystem exports.
 * ============================================================================ */

extern int mach_msg(void *msg, int option, unsigned int send_size,
                    unsigned int rcv_size, unsigned int rcv_name,
                    unsigned int timeout, unsigned int notify);
extern unsigned int mach_reply_port(void);
extern unsigned int mach_task_self(void);
extern int mach_port_deallocate(unsigned int task, unsigned int name);
extern int bootstrap_look_up(unsigned int bp, const void *service_name,
                             void *sp);

/* ============================================================================
 * Freestanding Constants
 * ============================================================================ */

/* Mach IPC */
#define _MACH_SEND_MSG          0x00000001
#define _MACH_RCV_MSG           0x00000002
#define _MSGH_BITS(r, l)        ((unsigned int)((r) | ((l) << 8)))
#define _MSG_TYPE_COPY_SEND     19
#define _MSG_TYPE_MAKE_SEND_ONCE 21

/* IOKit bootstrap service name (must match kernel iokit_init()) */
#define _IOKIT_SERVICE_NAME     "uk.co.avltree9798.iokit"

/*
 * IOKit Mach message IDs (must match kernel iokit_types.h).
 *
 * These are the real XNU MIG routine IDs from device.defs
 * (subsystem iokit 2800). Each routine/skip increments by 1.
 */
#define _IOKIT_MSG_BASE                     2800
#define _kIOServiceGetMatchingServicesMsg    (_IOKIT_MSG_BASE + 4)   /* 2804 */
#define _kIORegistryEntryGetPropertyMsg     (_IOKIT_MSG_BASE + 12)  /* 2812 */
#define _kIOServiceCloseMsg                 (_IOKIT_MSG_BASE + 16)  /* 2816 */
#define _kIOServiceOpenMsg                  (_IOKIT_MSG_BASE + 62)  /* 2862 */
#define _kIOConnectMapMemoryMsg             (_IOKIT_MSG_BASE + 63)  /* 2863 */
#define _kIOConnectUnmapMemoryMsg           (_IOKIT_MSG_BASE + 64)  /* 2864 */
#define _kIOConnectCallMethodMsg            (_IOKIT_MSG_BASE + 65)  /* 2865 */
#define _kIOServiceGetMatchingServiceMsg    (_IOKIT_MSG_BASE + 73)  /* 2873 */

/* IOReturn codes (must match kernel iokit_types.h — exact XNU values) */
#define _kIOReturnSuccess       0
#define _kIOReturnError         0xE00002BCu
#define _kIOReturnNoMemory      0xE00002BDu
#define _kIOReturnNoResources   0xE00002BEu
#define _kIOReturnIPCError      0xE00002BFu
#define _kIOReturnBadArgument   0xE00002C2u
#define _kIOReturnUnsupported   0xE00002C7u
#define _kIOReturnNotFound      0xE00002F0u

/* IO_OBJECT_NULL = MACH_PORT_NULL */
#define _IO_OBJECT_NULL         0

/* IOKit property key max (must match kernel io_property.h) */
#define _IO_PROP_KEY_MAX        64

/* External method limits (must match kernel iokit_types.h) */
#define _kIOExternalMethodScalarInputMax    16
#define _kIOExternalMethodScalarOutputMax   16

/* ============================================================================
 * Internal: IOKit Master Port
 *
 * On macOS, IOMasterPort() calls host_get_io_master_port() — a Mach RPC
 * to the host special port. On Kiseki, the kernel registers the IOKit
 * master port in the bootstrap namespace as "uk.co.avltree9798.iokit",
 * so we use bootstrap_look_up() to obtain it.
 *
 * The result is cached (the master port never changes for the lifetime
 * of a process). On macOS, __IOGetDefaultMasterPort() performs the
 * same caching via dispatch_once.
 *
 * Reference: IOKitLib.c __IOGetDefaultMasterPort()
 * ============================================================================ */

static unsigned int _iokit_master_port = 0;

static unsigned int _iokit_get_master_port(void)
{
    if (_iokit_master_port != 0)
        return _iokit_master_port;

    unsigned int port = 0;
    int kr = bootstrap_look_up(0, _IOKIT_SERVICE_NAME, &port);
    if (kr == 0 && port != 0) {
        _iokit_master_port = port;
        return port;
    }

    return 0;
}

/* ============================================================================
 * IOMasterPort / IOMainPort
 *
 * Obtains the IOKit master device port. On macOS:
 *   kern_return_t IOMasterPort(mach_port_t bootstrapPort,
 *                              mach_port_t *masterPort);
 *
 * The bootstrapPort parameter is ignored (macOS compatibility — only
 * used in simulator builds for bootstrap_look_up fallback).
 *
 * Reference: IOKitLib.c IOMasterPort()
 * ============================================================================ */

EXPORT const unsigned int kIOMasterPortDefault = 0;
EXPORT const unsigned int kIOMainPortDefault = 0;

EXPORT int IOMasterPort(unsigned int bootstrapPort, void *masterPort)
{
    (void)bootstrapPort;
    unsigned int *out = (unsigned int *)masterPort;

    unsigned int port = _iokit_get_master_port();
    if (port == 0) {
        *out = 0;
        return (int)_kIOReturnNotFound;
    }

    *out = port;
    return (int)_kIOReturnSuccess;
}

EXPORT int IOMainPort(unsigned int bootstrapPort, void *masterPort)
{
    return IOMasterPort(bootstrapPort, masterPort);
}

/* ============================================================================
 * IOServiceMatching
 *
 * On macOS:
 *   CFMutableDictionaryRef IOServiceMatching(const char *name);
 *
 * Creates a matching dictionary with key "IOProviderClass" set to name.
 * On macOS this returns a CFMutableDictionaryRef. Since we don't have
 * CoreFoundation, we return an opaque pointer to the class name string.
 *
 * The returned "dictionary" is consumed (released) by
 * IOServiceGetMatchingService — on macOS via CFRelease, here a no-op.
 *
 * Reference: IOKitLib.c IOServiceMatching() -> MakeOneStringProp()
 * ============================================================================ */

EXPORT void *IOServiceMatching(const void *name)
{
    return (void *)name;
}

/* ============================================================================
 * IOServiceNameMatching
 *
 * On macOS:
 *   CFMutableDictionaryRef IOServiceNameMatching(const char *name);
 *
 * Creates a matching dictionary with key "IONameMatch" set to name.
 * Same simplification as IOServiceMatching.
 *
 * Reference: IOKitLib.c IOServiceNameMatching()
 * ============================================================================ */

EXPORT void *IOServiceNameMatching(const void *name)
{
    return (void *)name;
}

/* ============================================================================
 * IOServiceGetMatchingService
 *
 * On macOS:
 *   io_service_t IOServiceGetMatchingService(mach_port_t mainPort,
 *                                            CFDictionaryRef matching);
 *
 * Looks up the first IOService matching the given dictionary.
 * ALWAYS CONSUMES one reference to the matching dictionary (CFRelease).
 *
 * If mainPort is MACH_PORT_NULL (kIOMasterPortDefault), internally
 * calls __IOGetDefaultMasterPort() to obtain the real port.
 *
 * Sends kIOServiceGetMatchingServiceMsg to the IOKit master port.
 *
 * Wire format (must match kernel iokit_mach.c):
 *   Request: hdr + match_key_count(u32) + class_name[128]
 *   Reply:   hdr + retcode(u32) + service_port(u32)
 *
 * Reference: IOKitLib.c IOServiceGetMatchingService()
 * ============================================================================ */

struct _iokit_get_matching_request {
    /* mach_msg_header_t: 24 bytes */
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    /* Body */
    unsigned int    match_key_count;
    char            class_name[128];
};

struct _iokit_get_matching_reply {
    /* mach_msg_header_t: 24 bytes */
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    /* Body */
    unsigned int    retcode;
    unsigned int    service_port;
    /* Trailer */
    unsigned int    trailer_type;
    unsigned int    trailer_size;
};

EXPORT unsigned int IOServiceGetMatchingService(unsigned int masterPort,
                                                void *matching)
{
    /*
     * On macOS, matching is CFRelease'd here. For us, matching is just
     * a const char* — the "release" is a no-op.
     */
    const char *class_name = (const char *)matching;
    if (class_name == (void *)0)
        return _IO_OBJECT_NULL;

    /* If mainPort is 0 (kIOMasterPortDefault), get the default */
    unsigned int master = masterPort;
    if (master == 0)
        master = _iokit_get_master_port();
    if (master == 0)
        return _IO_OBJECT_NULL;

    unsigned int reply_port = mach_reply_port();
    if (reply_port == 0)
        return _IO_OBJECT_NULL;

    struct _iokit_get_matching_request req;
    for (unsigned int i = 0; i < sizeof(req); i++)
        ((unsigned char *)&req)[i] = 0;

    req.msgh_bits = _MSGH_BITS(_MSG_TYPE_COPY_SEND, _MSG_TYPE_MAKE_SEND_ONCE);
    req.msgh_size = sizeof(req);
    req.msgh_remote_port = master;
    req.msgh_local_port = reply_port;
    req.msgh_id = _kIOServiceGetMatchingServiceMsg;
    req.match_key_count = 1;

    unsigned int j = 0;
    while (class_name[j] != '\0' && j < sizeof(req.class_name) - 1) {
        req.class_name[j] = class_name[j];
        j++;
    }
    req.class_name[j] = '\0';

    int kr = mach_msg(&req, _MACH_SEND_MSG | _MACH_RCV_MSG,
                      sizeof(req), sizeof(struct _iokit_get_matching_reply),
                      reply_port, 0, 0);
    if (kr != 0)
        return _IO_OBJECT_NULL;

    struct _iokit_get_matching_reply *reply =
        (struct _iokit_get_matching_reply *)(void *)&req;

    if (reply->retcode != _kIOReturnSuccess)
        return _IO_OBJECT_NULL;

    return reply->service_port;
}

/* ============================================================================
 * IOServiceOpen
 *
 * On macOS:
 *   kern_return_t IOServiceOpen(io_service_t service,
 *                               task_port_t owningTask,
 *                               uint32_t type,
 *                               io_connect_t *connect);
 *
 * Opens a connection to an IOService, creating an IOUserClient.
 * Internally calls io_service_open_extended() MIG RPC.
 *
 * Wire format (must match kernel iokit_mach.c):
 *   Request: hdr + connect_type(u32)
 *   Reply:   hdr + retcode(u32) + connect_port(u32)
 *
 * Reference: IOKitLib.c IOServiceOpen()
 * ============================================================================ */

struct _iokit_service_open_request {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    unsigned int    connect_type;
};

struct _iokit_service_open_reply {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    unsigned int    retcode;
    unsigned int    connect_port;
    unsigned int    trailer_type;
    unsigned int    trailer_size;
};

EXPORT int IOServiceOpen(unsigned int service, unsigned int owningTask,
                         unsigned int type, void *connect)
{
    (void)owningTask;   /* Kernel identifies caller task implicitly */

    unsigned int *out = (unsigned int *)connect;
    *out = 0;

    if (service == 0)
        return (int)_kIOReturnBadArgument;

    unsigned int reply_port = mach_reply_port();
    if (reply_port == 0)
        return (int)_kIOReturnNoResources;

    /*
     * Use a union to ensure the buffer is large enough for BOTH the
     * request (sent) and reply (received). On macOS the MIG-generated
     * stubs always declare a union of the request and reply structs
     * for exactly this reason.
     */
    union {
        struct _iokit_service_open_request  req;
        struct _iokit_service_open_reply    reply;
    } msg;

    for (unsigned int i = 0; i < sizeof(msg); i++)
        ((unsigned char *)&msg)[i] = 0;

    msg.req.msgh_bits = _MSGH_BITS(_MSG_TYPE_COPY_SEND, _MSG_TYPE_MAKE_SEND_ONCE);
    msg.req.msgh_size = sizeof(msg.req);
    msg.req.msgh_remote_port = service;
    msg.req.msgh_local_port = reply_port;
    msg.req.msgh_id = _kIOServiceOpenMsg;
    msg.req.connect_type = type;

    int kr = mach_msg(&msg, _MACH_SEND_MSG | _MACH_RCV_MSG,
                      sizeof(msg.req),
                      sizeof(struct _iokit_service_open_reply),
                      reply_port, 0, 0);
    if (kr != 0)
        return (int)_kIOReturnIPCError;

    struct _iokit_service_open_reply *reply = &msg.reply;

    if (reply->retcode != _kIOReturnSuccess) {
        *out = 0;
        return (int)reply->retcode;
    }

    *out = reply->connect_port;
    return (int)_kIOReturnSuccess;
}

/* ============================================================================
 * IOServiceClose
 *
 * On macOS:
 *   kern_return_t IOServiceClose(io_connect_t connect);
 *
 * Closes a user client connection. On macOS, this ALSO calls
 * IOObjectRelease(connect) — the caller must NOT release the
 * connection handle separately after calling IOServiceClose().
 *
 * Wire format:
 *   Request: hdr only
 *   Reply:   hdr + retcode(u32)
 *
 * Reference: IOKitLib.c IOServiceClose()
 * ============================================================================ */

struct _iokit_service_close_request {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
};

struct _iokit_service_close_reply {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    unsigned int    retcode;
    unsigned int    trailer_type;
    unsigned int    trailer_size;
};

EXPORT int IOServiceClose(unsigned int connect)
{
    if (connect == 0)
        return (int)_kIOReturnBadArgument;

    unsigned int reply_port = mach_reply_port();
    if (reply_port == 0)
        return (int)_kIOReturnNoResources;

    /*
     * Use a union to ensure the buffer is large enough for BOTH the
     * request (sent) and reply (received). On macOS the MIG-generated
     * stubs always declare a union of the request and reply structs.
     */
    union {
        struct _iokit_service_close_request  req;
        struct _iokit_service_close_reply    reply;
    } msg;

    for (unsigned int i = 0; i < sizeof(msg); i++)
        ((unsigned char *)&msg)[i] = 0;

    msg.req.msgh_bits = _MSGH_BITS(_MSG_TYPE_COPY_SEND, _MSG_TYPE_MAKE_SEND_ONCE);
    msg.req.msgh_size = sizeof(msg.req);
    msg.req.msgh_remote_port = connect;
    msg.req.msgh_local_port = reply_port;
    msg.req.msgh_id = _kIOServiceCloseMsg;

    int kr = mach_msg(&msg, _MACH_SEND_MSG | _MACH_RCV_MSG,
                      sizeof(msg.req),
                      sizeof(struct _iokit_service_close_reply),
                      reply_port, 0, 0);

    /*
     * On macOS, IOServiceClose() calls IOObjectRelease(connect) after
     * io_service_close(). We do the same — deallocate the send right.
     * The caller must NOT call IOObjectRelease() on connect after this.
     */
    mach_port_deallocate(mach_task_self(), connect);

    if (kr != 0)
        return (int)_kIOReturnIPCError;

    struct _iokit_service_close_reply *reply = &msg.reply;

    return (int)reply->retcode;
}

/* ============================================================================
 * IOConnectCallMethod
 *
 * On macOS:
 *   kern_return_t IOConnectCallMethod(
 *       mach_port_t     connection,
 *       uint32_t        selector,
 *       const uint64_t *input,
 *       uint32_t        inputCnt,
 *       const void     *inputStruct,
 *       size_t          inputStructCnt,
 *       uint64_t       *output,
 *       uint32_t       *outputCnt,
 *       void           *outputStruct,
 *       size_t         *outputStructCnt);
 *
 * The universal method for calling IOUserClient external methods.
 * Internally calls io_connect_method() MIG RPC.
 *
 * Wire format (must match kernel iokit_mach.c):
 *   Request: hdr + selector(u32) + scalarInCnt(u32) + structInSz(u32)
 *            + scalarOutCnt(u32) + structOutSz(u32) + payload[]
 *   Reply:   hdr + retcode(u32) + scalarOutCnt(u32) + structOutSz(u32)
 *            + payload[]
 *
 * Reference: IOKitLib.c IOConnectCallMethod()
 * ============================================================================ */

EXPORT int IOConnectCallMethod(
    unsigned int        connect,
    unsigned int        selector,
    const void          *scalarInput,       /* const uint64_t[] */
    unsigned int        scalarInputCount,
    const void          *structureInput,     /* const void* */
    unsigned long       structureInputSize,
    void                *scalarOutput,       /* uint64_t[] */
    void                *scalarOutputCount,  /* uint32_t* in/out */
    void                *structureOutput,    /* void* */
    void                *structureOutputSize /* size_t* in/out */)
{
    if (connect == 0)
        return (int)_kIOReturnBadArgument;

    /* Extract expected output counts (NULL-safe, matching macOS) */
    unsigned int scalar_out_cnt = 0;
    unsigned int struct_out_sz = 0;
    if (scalarOutputCount != (void *)0)
        scalar_out_cnt = *(unsigned int *)scalarOutputCount;
    if (structureOutputSize != (void *)0)
        struct_out_sz = (unsigned int)(*(unsigned long *)structureOutputSize);

    if (scalarInputCount > _kIOExternalMethodScalarInputMax)
        return (int)_kIOReturnBadArgument;
    if (scalar_out_cnt > _kIOExternalMethodScalarOutputMax)
        return (int)_kIOReturnBadArgument;

    /*
     * Build the request in a 4096-byte stack buffer.
     *
     * Layout:
     *   [24] mach_msg_header_t
     *   [4]  selector
     *   [4]  scalar_input_count
     *   [4]  struct_input_size
     *   [4]  scalar_output_count
     *   [4]  struct_output_size
     *   [N]  payload: uint64_t scalars + struct bytes
     */
    unsigned char msg_buf[4096];
    for (unsigned int i = 0; i < sizeof(msg_buf); i++)
        msg_buf[i] = 0;

    unsigned int hdr_fields_size = 24 + 5 * 4;
    unsigned int payload_size = scalarInputCount * 8
                              + (unsigned int)structureInputSize;
    unsigned int send_size = hdr_fields_size + payload_size;

    if (send_size > sizeof(msg_buf))
        return (int)_kIOReturnBadArgument;

    unsigned int reply_port = mach_reply_port();
    if (reply_port == 0)
        return (int)_kIOReturnNoResources;

    unsigned int *u32 = (unsigned int *)msg_buf;
    u32[0] = _MSGH_BITS(_MSG_TYPE_COPY_SEND, _MSG_TYPE_MAKE_SEND_ONCE);
    u32[1] = send_size;
    u32[2] = connect;
    u32[3] = reply_port;
    u32[4] = 0;
    *(int *)&u32[5] = (int)_kIOConnectCallMethodMsg;

    u32[6] = selector;
    u32[7] = scalarInputCount;
    u32[8] = (unsigned int)structureInputSize;
    u32[9] = scalar_out_cnt;
    u32[10] = struct_out_sz;

    /* Copy scalar inputs (uint64_t each) */
    unsigned char *payload = msg_buf + hdr_fields_size;
    if (scalarInputCount > 0 && scalarInput != (void *)0) {
        const unsigned char *src = (const unsigned char *)scalarInput;
        for (unsigned int i = 0; i < scalarInputCount * 8; i++)
            payload[i] = src[i];
    }

    /* Copy structure input */
    if (structureInputSize > 0 && structureInput != (void *)0) {
        const unsigned char *src = (const unsigned char *)structureInput;
        unsigned char *dst = payload + scalarInputCount * 8;
        for (unsigned long i = 0; i < structureInputSize; i++)
            dst[i] = src[i];
    }

    /* Reply size */
    unsigned int reply_hdr_size = 24 + 3 * 4;
    unsigned int reply_payload_size = scalar_out_cnt * 8 + struct_out_sz;
    unsigned int rcv_size = reply_hdr_size + reply_payload_size + 8;
    if (rcv_size > sizeof(msg_buf))
        rcv_size = sizeof(msg_buf);

    int kr = mach_msg(msg_buf, _MACH_SEND_MSG | _MACH_RCV_MSG,
                      send_size, rcv_size, reply_port, 0, 0);
    if (kr != 0)
        return (int)_kIOReturnIPCError;

    /* Parse reply */
    u32 = (unsigned int *)msg_buf;
    unsigned int retcode = u32[6];
    unsigned int actual_scalar_out = u32[7];
    unsigned int actual_struct_out = u32[8];

    if (retcode != _kIOReturnSuccess)
        return (int)retcode;

    /* Copy scalar outputs */
    unsigned char *reply_payload = msg_buf + reply_hdr_size;
    if (scalarOutput != (void *)0 && actual_scalar_out > 0) {
        unsigned int copy_cnt = actual_scalar_out;
        if (copy_cnt > scalar_out_cnt)
            copy_cnt = scalar_out_cnt;
        unsigned char *dst = (unsigned char *)scalarOutput;
        for (unsigned int i = 0; i < copy_cnt * 8; i++)
            dst[i] = reply_payload[i];
        if (scalarOutputCount != (void *)0)
            *(unsigned int *)scalarOutputCount = copy_cnt;
    }

    /* Copy structure output */
    if (structureOutput != (void *)0 && actual_struct_out > 0) {
        unsigned int copy_sz = actual_struct_out;
        if (copy_sz > struct_out_sz)
            copy_sz = struct_out_sz;
        unsigned char *src = reply_payload + actual_scalar_out * 8;
        unsigned char *dst = (unsigned char *)structureOutput;
        for (unsigned int i = 0; i < copy_sz; i++)
            dst[i] = src[i];
        if (structureOutputSize != (void *)0)
            *(unsigned long *)structureOutputSize = copy_sz;
    }

    return (int)_kIOReturnSuccess;
}

/* ============================================================================
 * IOConnectCallScalarMethod — Convenience wrapper
 *
 * Reference: IOKitLib.c IOConnectCallScalarMethod()
 * ============================================================================ */

EXPORT int IOConnectCallScalarMethod(
    unsigned int        connect,
    unsigned int        selector,
    const void          *input,
    unsigned int        inputCount,
    void                *output,
    void                *outputCount)
{
    return IOConnectCallMethod(connect, selector,
                               input, inputCount,
                               (void *)0, 0,
                               output, outputCount,
                               (void *)0, (void *)0);
}

/* ============================================================================
 * IOConnectCallStructMethod — Convenience wrapper
 *
 * Reference: IOKitLib.c IOConnectCallStructMethod()
 * ============================================================================ */

EXPORT int IOConnectCallStructMethod(
    unsigned int        connect,
    unsigned int        selector,
    const void          *inputStruct,
    unsigned long       inputStructCnt,
    void                *outputStruct,
    void                *outputStructCnt)
{
    return IOConnectCallMethod(connect, selector,
                               (void *)0, 0,
                               inputStruct, inputStructCnt,
                               (void *)0, (void *)0,
                               outputStruct, outputStructCnt);
}

/* ============================================================================
 * IOConnectMapMemory64 / IOConnectMapMemory
 *
 * On macOS:
 *   kern_return_t IOConnectMapMemory64(
 *       io_connect_t        connect,
 *       uint32_t            memoryType,
 *       task_port_t         intoTask,
 *       mach_vm_address_t  *atAddress,
 *       mach_vm_size_t     *ofSize,
 *       IOOptionBits        options);
 *
 * Internally calls io_connect_map_memory_into_task() MIG RPC.
 *
 * Wire format (must match kernel iokit_mach.c):
 *   Request: hdr + memory_type(u32) + options(u32)
 *   Reply:   hdr + retcode(u32) + [pad](u32) + address(u64) + size(u64)
 *
 * Reference: IOKitLib.c IOConnectMapMemory64()
 * ============================================================================ */

struct _iokit_map_memory_request {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    unsigned int    memory_type;
    unsigned int    options;
};

struct _iokit_map_memory_reply {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    unsigned int    retcode;
    unsigned int    _pad0;
    unsigned long   address;
    unsigned long   size;
    unsigned int    trailer_type;
    unsigned int    trailer_size;
};

EXPORT int IOConnectMapMemory64(
    unsigned int    connect,
    unsigned int    memoryType,
    unsigned int    intoTask,
    void            *address,
    void            *size,
    unsigned int    options)
{
    (void)intoTask;

    if (connect == 0 || address == (void *)0 || size == (void *)0)
        return (int)_kIOReturnBadArgument;

    unsigned int reply_port = mach_reply_port();
    if (reply_port == 0)
        return (int)_kIOReturnNoResources;

    /*
     * Use a union to ensure the buffer is large enough for BOTH the
     * request (sent) and reply (received). On macOS the MIG-generated
     * stubs always declare a union of the request and reply structs.
     *
     * Without this, the reply (56 bytes with trailer) would overflow
     * the request struct (32 bytes), corrupting the user stack.
     */
    union {
        struct _iokit_map_memory_request  req;
        struct _iokit_map_memory_reply    reply;
    } msg;

    for (unsigned int i = 0; i < sizeof(msg); i++)
        ((unsigned char *)&msg)[i] = 0;

    msg.req.msgh_bits = _MSGH_BITS(_MSG_TYPE_COPY_SEND, _MSG_TYPE_MAKE_SEND_ONCE);
    msg.req.msgh_size = sizeof(msg.req);
    msg.req.msgh_remote_port = connect;
    msg.req.msgh_local_port = reply_port;
    msg.req.msgh_id = _kIOConnectMapMemoryMsg;
    msg.req.memory_type = memoryType;
    msg.req.options = options;

    int kr = mach_msg(&msg, _MACH_SEND_MSG | _MACH_RCV_MSG,
                      sizeof(msg.req),
                      sizeof(struct _iokit_map_memory_reply),
                      reply_port, 0, 0);
    if (kr != 0)
        return (int)_kIOReturnIPCError;

    struct _iokit_map_memory_reply *reply = &msg.reply;

    if (reply->retcode != _kIOReturnSuccess)
        return (int)reply->retcode;

    *(unsigned long *)address = reply->address;
    *(unsigned long *)size = reply->size;

    return (int)_kIOReturnSuccess;
}

EXPORT int IOConnectMapMemory(
    unsigned int    connect,
    unsigned int    memoryType,
    unsigned int    intoTask,
    void            *address,
    void            *size,
    unsigned int    options)
{
    return IOConnectMapMemory64(connect, memoryType, intoTask,
                                address, size, options);
}

/* ============================================================================
 * IORegistryEntryGetProperty
 *
 * Gets a property value from an IOKit registry entry.
 *
 * Wire format (must match kernel iokit_mach.c):
 *   Request: hdr + key[IO_PROP_KEY_MAX]
 *   Reply:   hdr + retcode(u32) + value_type(u32) + value_size(u32)
 *            + value_data[256]
 *
 * Reference: IOKitLib.c IORegistryEntryGetProperty()
 * ============================================================================ */

struct _iokit_get_property_request {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    char            key[64];
};

struct _iokit_get_property_reply {
    unsigned int    msgh_bits;
    unsigned int    msgh_size;
    unsigned int    msgh_remote_port;
    unsigned int    msgh_local_port;
    unsigned int    msgh_voucher_port;
    int             msgh_id;
    unsigned int    retcode;
    unsigned int    value_type;
    unsigned int    value_size;
    unsigned char   value_data[256];
    unsigned int    trailer_type;
    unsigned int    trailer_size;
};

EXPORT int IORegistryEntryGetProperty(
    unsigned int    entry,
    const void      *key,
    void            *value,
    void            *valueSize)
{
    if (entry == 0 || key == (void *)0)
        return (int)_kIOReturnBadArgument;

    unsigned int reply_port = mach_reply_port();
    if (reply_port == 0)
        return (int)_kIOReturnNoResources;

    /*
     * Use a union to ensure the buffer is large enough for BOTH the
     * request (sent) and reply (received). On macOS the MIG-generated
     * stubs always declare a union of the request and reply structs.
     *
     * This is especially critical here: the reply (300 bytes with
     * 256-byte value_data) is much larger than the request (88 bytes).
     */
    union {
        struct _iokit_get_property_request  req;
        struct _iokit_get_property_reply    reply;
    } msg;

    for (unsigned int i = 0; i < sizeof(msg); i++)
        ((unsigned char *)&msg)[i] = 0;

    msg.req.msgh_bits = _MSGH_BITS(_MSG_TYPE_COPY_SEND, _MSG_TYPE_MAKE_SEND_ONCE);
    msg.req.msgh_size = sizeof(msg.req);
    msg.req.msgh_remote_port = entry;
    msg.req.msgh_local_port = reply_port;
    msg.req.msgh_id = _kIORegistryEntryGetPropertyMsg;

    const char *k = (const char *)key;
    unsigned int j = 0;
    while (k[j] != '\0' && j < sizeof(msg.req.key) - 1) {
        msg.req.key[j] = k[j];
        j++;
    }
    msg.req.key[j] = '\0';

    int kr = mach_msg(&msg, _MACH_SEND_MSG | _MACH_RCV_MSG,
                      sizeof(msg.req),
                      sizeof(struct _iokit_get_property_reply),
                      reply_port, 0, 0);
    if (kr != 0)
        return (int)_kIOReturnIPCError;

    struct _iokit_get_property_reply *reply = &msg.reply;

    if (reply->retcode != _kIOReturnSuccess)
        return (int)reply->retcode;

    if (value != (void *)0 && reply->value_size > 0) {
        unsigned int max_copy = reply->value_size;
        if (valueSize != (void *)0) {
            unsigned int caller_sz = *(unsigned int *)valueSize;
            if (max_copy > caller_sz)
                max_copy = caller_sz;
        }
        unsigned char *dst = (unsigned char *)value;
        for (unsigned int i = 0; i < max_copy; i++)
            dst[i] = reply->value_data[i];
    }

    if (valueSize != (void *)0)
        *(unsigned int *)valueSize = reply->value_size;

    return (int)_kIOReturnSuccess;
}

/* ============================================================================
 * IOObjectRelease
 *
 * On macOS:
 *   kern_return_t IOObjectRelease(io_object_t object);
 *
 * Simply calls mach_port_deallocate() to release one Mach send right.
 * When the last send right is released, the kernel receives a
 * no-senders notification and cleans up the kernel object.
 *
 * Reference: IOKitLib.c IOObjectRelease()
 * ============================================================================ */

EXPORT int IOObjectRelease(unsigned int object)
{
    if (object == 0)
        return (int)_kIOReturnSuccess;

    return mach_port_deallocate(mach_task_self(), object);
}

/* ============================================================================
 * IOObjectRetain
 *
 * On macOS:
 *   kern_return_t IOObjectRetain(io_object_t object);
 *
 * Uses mach_port_mod_refs to add one send right reference.
 *
 * Reference: IOKitLib.c IOObjectRetain()
 * ============================================================================ */

/* mach_port_mod_refs imported from libSystem */
extern int mach_port_mod_refs(unsigned int task, unsigned int name,
                              unsigned int right, int delta);

#define _MACH_PORT_RIGHT_SEND   0

EXPORT int IOObjectRetain(unsigned int object)
{
    if (object == 0)
        return (int)_kIOReturnBadArgument;

    return mach_port_mod_refs(mach_task_self(), object,
                              _MACH_PORT_RIGHT_SEND, 1);
}
