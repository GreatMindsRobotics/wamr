/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "handler.h"
#include "debug_engine.h"
#include "packets.h"
#include "utils.h"
#include "wasm_runtime.h"
#include "wasm_export.h"

#if defined(BH_PLATFORM_WINDOWS)
/* `getcwd` lives in `<direct.h>` as `_getcwd` on the Windows CRT. */
#include <direct.h>
#define getcwd _getcwd
#endif

/*
 * Note: A moderate MAX_PACKET_SIZE is ok because
 * LLDB queries our buffer size (via qSupported PacketSize)
 * and limits packet sizes accordingly.
 */

#if defined(DEBUG_MAX_PACKET_SIZE)
#define MAX_PACKET_SIZE DEBUG_MAX_PACKET_SIZE
#else
#define MAX_PACKET_SIZE (4096)
#endif

/*
 * Note: It's assumed that MAX_PACKET_SIZE is reasonably large.
 * See GetWorkingDir, WasmCallStack, etc.
 */
#if MAX_PACKET_SIZE < PATH_MAX || MAX_PACKET_SIZE < (2048 + 1)
#error MAX_PACKET_SIZE is too small
#endif

static char *tmpbuf;
static korp_mutex tmpbuf_lock;

int
wasm_debug_handler_init(void)
{
    int ret;
    tmpbuf = wasm_runtime_malloc(MAX_PACKET_SIZE);
    if (tmpbuf == NULL) {
        LOG_ERROR("debug-engine: Packet buffer allocation failure");
        return BHT_ERROR;
    }
    ret = os_mutex_init(&tmpbuf_lock);
    if (ret != BHT_OK) {
        wasm_runtime_free(tmpbuf);
        tmpbuf = NULL;
    }
    return ret;
}

void
wasm_debug_handler_deinit(void)
{
    wasm_runtime_free(tmpbuf);
    tmpbuf = NULL;
    os_mutex_destroy(&tmpbuf_lock);
}

void
handle_interrupt(WASMGDBServer *server)
{
    wasm_debug_instance_interrupt_all_threads(server->thread->debug_instance);
}

void
handle_general_set(WASMGDBServer *server, char *payload)
{
    const char *name;
    char *args;

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';

    name = payload;
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);

    if (!strcmp(name, "StartNoAckMode")) {
        server->noack = true;
        write_packet(server, "OK");
    }
    if (!strcmp(name, "ThreadSuffixSupported")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "ListThreadsInStopReply")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "EnableErrorStrings")) {
        write_packet(server, "OK");
    }
}

static void
process_xfer(WASMGDBServer *server, const char *name, char *args)
{
    const char *mode = args;

    args = strchr(args, ':');
    if (args)
        *args++ = '\0';

    if (!strcmp(name, "libraries") && !strcmp(mode, "read")) {
        // TODO: how to get current wasm file name?
        uint64 addr = wasm_debug_instance_get_load_addr(
            (WASMDebugInstance *)server->thread->debug_instance);
        os_mutex_lock(&tmpbuf_lock);
#if WASM_ENABLE_LIBC_WASI != 0
        char objname[128];
        if (!wasm_debug_instance_get_current_object_name(
                (WASMDebugInstance *)server->thread->debug_instance, objname,
                128)) {
            objname[0] = 0; /* use an empty string */
        }
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "l<library-list><library name=\"%s\"><section "
                 "address=\"0x%" PRIx64 "\"/></library></library-list>",
                 objname, addr);
#else
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "l<library-list><library name=\"%s\"><section "
                 "address=\"0x%" PRIx64 "\"/></library></library-list>",
                 "nobody.wasm", addr);
#endif
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
}

/* Forward declarations of helpers defined later in this file so the
 * Part G/H handlers (which come before them in source order to keep
 * the dispatch table compact) can reference them. */
static void
emit_err_reply(WASMGDBServer *server, const char *code, const char *msg);
static int32
decode_hex_bytes(const char *hex, uint8 *out, uint32 out_cap);

void
process_wasm_local(WASMGDBServer *server, char *args)
{
    int32 frame_index;
    int32 local_index;
    char buf[16];
    int32 size = 16;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "E01");
    if (sscanf(args, "%" PRId32 ";%" PRId32, &frame_index, &local_index) == 2) {
        ret = wasm_debug_instance_get_local(
            (WASMDebugInstance *)server->thread->debug_instance, frame_index,
            local_index, buf, &size);
        if (ret && size > 0) {
            mem2hex(buf, tmpbuf, size);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

/*
 * qWasmLocalSet:<frame-idx-hex>;<local-idx-hex>;<bytes-hex>
 *
 * Symmetric counterpart to qWasmLocal (subplan #4 Part H). Writes a
 * scalar value into a wasm local in the paused frame. The IW REPL
 * uses this to propagate scalar mutations performed by a fragment
 * back into the paused main frame.
 *
 * Reply (OK):  OK
 * Reply (Err): ERR:<code>:<msg-hex>:
 *   code ∈ { bad-request, no-frame, bad-size }
 */
void
process_wasm_local_set(WASMGDBServer *server, char *args)
{
    int32 frame_index, local_index;
    char *p;
    char buf[16];
    int32 byte_count;
    bool ok;

    os_mutex_lock(&tmpbuf_lock);

    if (sscanf(args, "%" PRId32 ";%" PRId32, &frame_index, &local_index) != 2) {
        emit_err_reply(server, "bad-request", "expected frame;local;bytes");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    /* Skip to the second `;` for the bytes blob. */
    p = strchr(args, ';');
    if (!p) {
        emit_err_reply(server, "bad-request", "missing local-idx separator");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    p = strchr(p + 1, ';');
    if (!p) {
        emit_err_reply(server, "bad-request", "missing bytes-hex separator");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    p++;

    byte_count = decode_hex_bytes(p, (uint8 *)buf, sizeof(buf));
    if (byte_count < 0 || (byte_count != 4 && byte_count != 8)) {
        emit_err_reply(server, "bad-size", "expected 4 or 8 bytes");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    ok = wasm_debug_instance_set_local(
        (WASMDebugInstance *)server->thread->debug_instance, frame_index,
        local_index, buf, byte_count);
    if (!ok) {
        emit_err_reply(server, "no-frame",
                       "frame/local out of range or type mismatch");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    snprintf(tmpbuf, MAX_PACKET_SIZE, "OK");
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
process_wasm_global(WASMGDBServer *server, char *args)
{
    int32 frame_index;
    int32 global_index;
    char buf[16];
    int32 size = 16;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "E01");
    if (sscanf(args, "%" PRId32 ";%" PRId32, &frame_index, &global_index)
        == 2) {
        ret = wasm_debug_instance_get_global(
            (WASMDebugInstance *)server->thread->debug_instance, frame_index,
            global_index, buf, &size);
        if (ret && size > 0) {
            mem2hex(buf, tmpbuf, size);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

/*
 * qWasmCall: invoke a wasm function while halted at a breakpoint.
 *
 * Request body: WasmCall:<funcname-hex>:<argbytes-hex>
 * Reply (OK):   OK:<retbytes-hex>:<stdout-hex>
 * Reply (Err):  ERR:<code>:<message-hex>:<stdout-hex>
 *
 * See Sculptor/plans/wamr_inferior_call_plan.md. This is the
 * synchronous skeleton — it parses the request, runs the call
 * against a derived exec_env that shares the paused module instance,
 * and sends the reply through the normal query-reply path. The
 * paused frame stays untouched because we never reuse the original
 * exec_env's stack.
 *
 * Limitations (tracked as follow-ups, not blockers for the
 * differential test infrastructure):
 *  - Synchronous: the handler blocks the gdbserver loop for the call
 *    duration. \x03 interruption requires the Part A2 worker thread.
 *  - No stdout capture: wasi fd_write goes to the host's normal sink.
 *    Part B2 adds a per-call override.
 */

/* Map WAMR's exception string to one of the trap codes the wire
 * format documents. Falls back to "trap" when nothing matches. */
static const char *
trap_code_from_exception(const char *exc)
{
    if (!exc || !*exc)
        return "trap";
    if (strstr(exc, "out of bounds"))
        return "bounds";
    if (strstr(exc, "integer overflow"))
        return "overflow";
    if (strstr(exc, "integer divide by zero")
        || strstr(exc, "integer divide overflow"))
        return "div0";
    if (strstr(exc, "stack overflow"))
        return "stackoverflow";
    if (strstr(exc, "unreachable"))
        return "panic";
    return "trap";
}

/* Cell count for one wasm value kind. i64/f64 take two 32-bit cells;
 * everything else (i32, f32, ref types) is one. */
static uint32
cells_for_kind(wasm_valkind_t k)
{
    return (k == WASM_I64 || k == WASM_F64) ? 2 : 1;
}

/* Decode an even-length ASCII hex string into a byte buffer. Returns
 * the number of bytes written, or -1 on malformed input. */
static int32
decode_hex_bytes(const char *hex, uint8 *out, uint32 out_cap)
{
    uint32 i, len;
    if (!hex)
        return 0;
    len = (uint32)strlen(hex);
    if (len % 2)
        return -1;
    if (len / 2 > out_cap)
        return -1;
    for (i = 0; i < len; i += 2) {
        char c1 = hex[i], c2 = hex[i + 1];
        int v1 = (c1 <= '9')   ? c1 - '0'
                 : (c1 <= 'F') ? c1 - 'A' + 10
                               : c1 - 'a' + 10;
        int v2 = (c2 <= '9')   ? c2 - '0'
                 : (c2 <= 'F') ? c2 - 'A' + 10
                               : c2 - 'a' + 10;
        if (v1 < 0 || v1 > 15 || v2 < 0 || v2 > 15)
            return -1;
        out[i / 2] = (uint8)((v1 << 4) | v2);
    }
    return (int32)(len / 2);
}

/* Emit ERR:<code>:<msg-hex>: into tmpbuf. Caller must hold
 * tmpbuf_lock. stdout-hex is always empty until Part B2 lands. */
static void
emit_err_reply(WASMGDBServer *server, const char *code, const char *msg)
{
    char msg_hex[512];
    int32 msg_len = (int32)strlen(msg);
    if (msg_len > (int32)(sizeof(msg_hex) / 2 - 1))
        msg_len = (int32)(sizeof(msg_hex) / 2 - 1);
    mem2hex((char *)msg, msg_hex, msg_len);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "ERR:%s:%s:", code, msg_hex);
    write_packet(server, tmpbuf);
}

/* ===================================================================
 * Side-module registry (subplan #4 Part G).
 *
 * The IW REPL ships compiled wasm fragments to the running target.
 * Each fragment becomes a side module that imports the main module's
 * memory + function table. We hold the bytes during chunked transfer,
 * then load + instantiate them when the host commits, and dispatch
 * qWasmCall against the resulting instance.
 *
 * Lifecycle: chunk transfer → commit (instantiate) → call → unload.
 * Embedded targets cap at one outstanding side module at a time; host
 * allows multiple. Memory budget enforced via per-module capacity cap.
 * =================================================================== */

#define SIDE_MODULE_MAX_BYTES (64 * 1024)
/* Fragments annotate every extern (function + memory) with
 * __attribute__((import_module("repl_host"))) — see
 * `Kiln/Codegen/FunctionEmitter.cs` fragment-mode branch. WAMR
 * reserves a handful of module names ("env", "wasi_*", ...) as
 * built-in, so we use a non-reserved name. */
#define SIDE_MAIN_REGISTRY_NAME "repl_host"

typedef struct WasmSideModule {
    uint32 handle;               /* 1-based; 0 = invalid */
    char *name;                  /* host-chosen, GUID-suffixed */
    uint8 *bytes;                /* accumulating wasm bytes */
    uint32 size;                 /* current append position */
    uint32 capacity;             /* allocated capacity */
    wasm_module_t module;        /* non-NULL after commit */
    wasm_module_inst_t instance; /* non-NULL after commit */
    /* Part I — cross-instance memory sharing. After instantiate, the
     * side instance's memories[0] pointer gets swapped to point at
     * the main instance's memories[0] so the side reads/writes main's
     * actual linear memory. We stash the side's original memory here
     * so destroy_side_module can restore it before deinstantiate
     * frees what it thinks it owns. NULL means no swap performed. */
    void *saved_memory;
    struct WasmSideModule *next;
} WasmSideModule;

static WasmSideModule *g_side_modules = NULL;
static uint32 g_next_side_handle = 1;
static bool g_main_registered = false;

/* Find an in-progress / loaded side module by host-chosen name. */
static WasmSideModule *
find_side_module_by_name(const char *name)
{
    WasmSideModule *m;
    for (m = g_side_modules; m; m = m->next)
        if (m->name && !strcmp(m->name, name))
            return m;
    return NULL;
}

static WasmSideModule *
find_side_module_by_handle(uint32 handle)
{
    WasmSideModule *m;
    for (m = g_side_modules; m; m = m->next)
        if (m->handle == handle)
            return m;
    return NULL;
}

static void
free_side_module(WasmSideModule *m)
{
    if (m->instance) {
        /* Part I: if we swapped main's memory into the side, restore
         * the side's original memory before deinstantiate so the
         * cleanup frees what the side actually owns, not main's
         * memory pages. */
        if (m->saved_memory) {
            WASMModuleInstance *side_real = (WASMModuleInstance *)m->instance;
            if (side_real->memory_count > 0)
                side_real->memories[0] = (WASMMemoryInstance *)m->saved_memory;
            m->saved_memory = NULL;
        }
        wasm_runtime_deinstantiate(m->instance);
    }
    if (m->module)
        wasm_runtime_unload(m->module);
    if (m->bytes)
        wasm_runtime_free(m->bytes);
    if (m->name)
        wasm_runtime_free(m->name);
    wasm_runtime_free(m);
}

/* Unlink from the list and free. */
static void
destroy_side_module(WasmSideModule *target)
{
    WasmSideModule **pp = &g_side_modules;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            free_side_module(target);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Register the main module under SIDE_MAIN_REGISTRY_NAME so side
 * modules' imports of the form `(import "main" "<sym>" ...)` resolve
 * at instantiation. Idempotent. Requires WAMR_BUILD_MULTI_MODULE=1 in
 * the build. */
static bool
ensure_main_registered(wasm_module_t main_module, char *err, size_t err_cap)
{
    if (g_main_registered)
        return true;
#if WASM_ENABLE_MULTI_MODULE != 0
    if (!wasm_runtime_register_module(SIDE_MAIN_REGISTRY_NAME, main_module, err,
                                      (uint32)err_cap))
        return false;
    g_main_registered = true;
    return true;
#else
    /* MULTI_MODULE disabled — IW REPL fragment loading isn't available
     * in this build. Returning false makes qWasmLoadSide reply with
     * an error if it's ever invoked, rather than silently appearing
     * to succeed. (Experiment: 2026-05-17 multi-push OOM isolation.) */
    (void)main_module;
    (void)err;
    (void)err_cap;
    return false;
#endif
}

/*
 * qWasmLoadSide:<name>:<chunk-idx-hex>:<chunk-total-hex>:<bytes-hex>
 *
 * Receive one chunk of a side module's wasm bytes. Replies "OK" for
 * non-final chunks. The final chunk (chunk-idx + 1 == chunk-total)
 * additionally validates + instantiates the module against the paused
 * main instance; reply is "OK:<handle-hex>:" on success or
 * "ERR:<code>:<msg-hex>:" on failure.
 *
 * Errors (final chunk):
 *  - bad-wasm     : wasm_runtime_load rejected the bytes
 *  - link-error   : instantiate failed (missing import, etc.)
 *  - no-memory    : allocation failed
 *  - no-main-inst : couldn't resolve the paused module instance
 */
void
process_wasm_load_side(WASMGDBServer *server, char *args)
{
    char *p, *name_start, *chunk_idx_str, *chunk_total_str, *bytes_hex;
    uint32 chunk_idx, chunk_total;
    int32 bytes_decoded;
    WasmSideModule *m;

    os_mutex_lock(&tmpbuf_lock);

    /* Parse name:chunk-idx:chunk-total:bytes-hex. */
    name_start = args;
    p = strchr(name_start, ':');
    if (!p) {
        emit_err_reply(server, "bad-request", "missing chunk-idx");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    *p++ = '\0';
    chunk_idx_str = p;
    p = strchr(chunk_idx_str, ':');
    if (!p) {
        emit_err_reply(server, "bad-request", "missing chunk-total");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    *p++ = '\0';
    chunk_total_str = p;
    p = strchr(chunk_total_str, ':');
    if (!p) {
        emit_err_reply(server, "bad-request", "missing bytes-hex");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    *p++ = '\0';
    bytes_hex = p;

    chunk_idx = (uint32)strtoul(chunk_idx_str, NULL, 16);
    chunk_total = (uint32)strtoul(chunk_total_str, NULL, 16);
    if (chunk_total == 0 || chunk_idx >= chunk_total) {
        emit_err_reply(server, "bad-request", "invalid chunk indices");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    /* Find or create the entry on chunk 0. */
    m = find_side_module_by_name(name_start);
    if (chunk_idx == 0) {
        if (m) {
            /* Restart: free prior accumulated bytes but keep the name. */
            if (m->module || m->instance) {
                emit_err_reply(server, "bad-request",
                               "module already committed under this name");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }
            if (m->bytes) {
                wasm_runtime_free(m->bytes);
                m->bytes = NULL;
            }
            m->size = 0;
            m->capacity = 0;
        }
        else {
            m = wasm_runtime_malloc(sizeof(WasmSideModule));
            if (!m) {
                emit_err_reply(server, "no-memory",
                               "side-module struct alloc failed");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }
            memset(m, 0, sizeof(*m));
            m->name = bh_strdup(name_start);
            if (!m->name) {
                wasm_runtime_free(m);
                emit_err_reply(server, "no-memory",
                               "side-module name alloc failed");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }
            m->next = g_side_modules;
            g_side_modules = m;
        }
    }
    else if (!m) {
        emit_err_reply(server, "bad-request", "chunk for unknown module name");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    /* Decode + append the chunk's bytes. */
    {
        uint32 hex_len = (uint32)strlen(bytes_hex);
        uint32 chunk_bytes = hex_len / 2;
        uint32 new_size = m->size + chunk_bytes;
        if (new_size > SIDE_MODULE_MAX_BYTES) {
            emit_err_reply(server, "no-memory",
                           "side-module exceeds SIDE_MODULE_MAX_BYTES");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        if (new_size > m->capacity) {
            uint32 new_cap = m->capacity ? m->capacity * 2 : 4096;
            while (new_cap < new_size)
                new_cap *= 2;
            if (new_cap > SIDE_MODULE_MAX_BYTES)
                new_cap = SIDE_MODULE_MAX_BYTES;
            uint8 *grown = wasm_runtime_malloc(new_cap);
            if (!grown) {
                emit_err_reply(server, "no-memory",
                               "side-module realloc failed");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }
            if (m->bytes) {
                memcpy(grown, m->bytes, m->size);
                wasm_runtime_free(m->bytes);
            }
            m->bytes = grown;
            m->capacity = new_cap;
        }
        bytes_decoded = decode_hex_bytes(bytes_hex, m->bytes + m->size,
                                         m->capacity - m->size);
        if (bytes_decoded < 0) {
            emit_err_reply(server, "bad-request", "malformed chunk hex");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        m->size += (uint32)bytes_decoded;
    }

    /* Non-final chunk: ack and wait for more. */
    if (chunk_idx + 1 < chunk_total) {
        snprintf(tmpbuf, MAX_PACKET_SIZE, "OK");
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    /* Final chunk: validate + instantiate. */
    {
        WASMDebugInstance *debug_inst;
        WASMExecEnv *paused_env;
        wasm_module_inst_t main_inst;
        wasm_module_t side_module;
        wasm_module_inst_t side_inst;
        char err[256] = { 0 };

        debug_inst = (WASMDebugInstance *)server->thread->debug_instance;
        paused_env = wasm_debug_instance_get_current_env(debug_inst);
        if (!paused_env) {
            emit_err_reply(server, "no-main-inst", "no paused exec_env");
            destroy_side_module(m);
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        main_inst = wasm_runtime_get_module_inst(paused_env);
        if (!main_inst) {
            emit_err_reply(server, "no-main-inst",
                           "no module instance on paused exec_env");
            destroy_side_module(m);
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }

        /* Make the main module discoverable to the side module's
         * import resolver. Idempotent across loads. */
        {
            wasm_module_t main_module = wasm_runtime_get_module(main_inst);
            if (!main_module) {
                emit_err_reply(server, "no-main-inst",
                               "wasm_runtime_get_module returned NULL");
                destroy_side_module(m);
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }
            if (!ensure_main_registered(main_module, err, sizeof(err))) {
                emit_err_reply(server, "link-error",
                               err[0] ? err : "register failed");
                destroy_side_module(m);
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }
        }

        err[0] = '\0';
        side_module = wasm_runtime_load(m->bytes, m->size, err, sizeof(err));
        if (!side_module) {
            emit_err_reply(server, "bad-wasm", err[0] ? err : "load failed");
            destroy_side_module(m);
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        m->module = side_module;

        /* Sculptor IW REPL: tell wasm_allocate_linear_memory
         * and wasm_runtime.c's data-segment-init loop to skip the
         * side module's real 64 KiB linear memory allocation +
         * data-segment copy. The Part I swap below replaces
         * memories[0] with main's memory anyway, so the side's own
         * memory is purely dead weight — and on a tight embedded heap
         * a 64 KiB alloc reliably fails after main is loaded. The
         * flag is cleared immediately after instantiate so main wasm
         * loads (the other call site of wasm_runtime_instantiate)
         * keep getting real memory. */
        {
            extern bool g_clay_skip_side_linear_memory;
            g_clay_skip_side_linear_memory = true;
            side_inst = wasm_runtime_instantiate(
                side_module,
                /*default_stack_size=*/8 * 1024,
                /*host_managed_heap_size=*/0, err, sizeof(err));
            g_clay_skip_side_linear_memory = false;
        }
        if (!side_inst) {
            emit_err_reply(server, "link-error",
                           err[0] ? err : "instantiate failed");
            destroy_side_module(m);
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        m->instance = side_inst;
        m->handle = g_next_side_handle++;

        /* Part I — share main's memory pages with the side.
         * WAMR's multi-module support re-instantiates submodules
         * rather than sharing an already-instantiated instance.
         * The IW REPL needs the OPPOSITE: the fragment must read
         * and write the running main module's actual memory so that
         * captured composites and string buffers point at the right
         * bytes. We achieve that by swapping the side instance's
         * memories[0] WASMMemoryInstance pointer to point at main's.
         * The side's wasm code then loads + stores against main's
         * pages; before deinstantiate we restore the original so
         * cleanup frees the side's own (otherwise-unused) memory. */
        {
            WASMModuleInstance *side_real = (WASMModuleInstance *)side_inst;
            WASMModuleInstance *main_real = (WASMModuleInstance *)main_inst;
            if (side_real->memory_count > 0 && main_real->memory_count > 0) {
                m->saved_memory = side_real->memories[0];
                side_real->memories[0] = main_real->memories[0];

                /* Task #80: relocate fragment's data segments into
                 * main's memory. At instantiate, WAMR copied each
                 * data segment's bytes into the side's *own* memory
                 * pages — the swap above orphaned them. Walk the
                 * data segments and memcpy each into main's memory
                 * at its wasm-declared offset.
                 *
                 * Layout contract (FragmentCompiler + HostWasmBuilder):
                 *   - Fragment is linked `--stack-first
                 *     --global-base=24576` → fragment stack at
                 *     [16384, 24576), data segments at offsets
                 *     >= 24576.
                 *   - Main is linked `--global-base=32768`,
                 *     -z,stack-size=16384 → main's wasm stack at
                 *     [0, 16384), data at >= 32768. Region
                 *     [16384, 32768) is reserved for fragment use.
                 *   Fragment's data lands in main's reserved window
                 *   [24576, 32768) with no collision. */
                WASMModule *side_mod = side_real->module;
                WASMMemoryInstance *main_mem = main_real->memories[0];
                if (side_mod && main_mem && main_mem->memory_data) {
                    uint64 main_size = main_mem->memory_data_size;
                    for (uint32 si = 0; si < side_mod->data_seg_count; si++) {
                        WASMDataSeg *seg = side_mod->data_segments[si];
                        if (!seg)
                            continue;
#if WASM_ENABLE_BULK_MEMORY != 0
                        if (seg->is_passive)
                            continue;
#endif
                        uint32 off = (uint32)seg->base_offset.u.unary.v.i32;
                        uint32 len = seg->data_length;
                        if ((uint64)off + len <= main_size) {
                            memcpy(main_mem->memory_data + off, seg->data, len);
                        }
                    }
                }

                /* Task #84: patch fragment's __stack_pointer.
                 * wasm-ld initializes __sp to the stack-size value
                 * (with --stack-first), placing fragment's stack at
                 * [0, stack-size) — SAME region as main's own wasm
                 * stack at [0, 16384), which collides catastrophically
                 * once the memory pointer is shared. Patch __sp to
                 * 24576 so fragment's stack writes land in main's
                 * reserved [16384, 24576) gap (8 KiB stack region
                 * above main's stack).
                 *
                 * wasm-ld convention: the first mutable i32 global
                 * is __stack_pointer. The fragment side module
                 * produced by FragmentCompiler has exactly one
                 * mutable global (verified via wasm-objdump). */
                if (side_real->e && side_real->e->globals) {
                    for (uint32 gi = 0; gi < side_real->e->global_count; gi++) {
                        WASMGlobalInstance *g = &side_real->e->globals[gi];
                        if (g->type == VALUE_TYPE_I32 && g->is_mutable) {
                            g->initial_value.i32 = 24576;
                            *(uint32 *)(side_real->global_data
                                        + g->data_offset) = 24576;
                            break;
                        }
                    }
                }
            }

            /* Re-bind the side's repl_host function imports to point
             * at main_inst's actual function table. WAMR's
             * multi-module instantiate cloned repl_host into a
             * separate instance — the side's import-fn slots refer
             * to the clone's functions, NOT to main's. That's why
             * Cx12 (a fragment importing a user-defined Clay fn from
             * main) traps as "unlinked": the clone's function exists
             * but has no native pointer and the wasm-side dispatcher
             * routes to it.
             *
             * For every side function import whose module_name is
             * SIDE_MAIN_REGISTRY_NAME, look up its name in main_inst's
             * export table and overwrite import_module_inst /
             * import_func_inst. Then the cross-module call goes to
             * main's actual function, running on main's stack frame. */
#if WASM_ENABLE_MULTI_MODULE != 0
            /* The import_module_inst / import_func_inst fields only
             * exist when WAMR is built with multi-module support,
             * which every OpenBrick consumer enables. Without it, an
             * IW REPL fragment referencing a user-defined Clay
             * function from main cannot invoke; fragments calling
             * only clay_* runtime functions (NativeSymbols, not
             * wasm-to-wasm imports) would still work. */
            if (side_real->e && side_real->e->functions) {
                WASMModule *side_mod = side_real->module;
                uint32 i;
                for (i = 0; i < side_mod->import_function_count; i++) {
                    WASMImport *imp = &side_mod->import_functions[i];
                    if (!imp->u.function.module_name
                        || strcmp(imp->u.function.module_name,
                                  SIDE_MAIN_REGISTRY_NAME)
                               != 0) {
                        continue;
                    }
                    WASMFunctionInstance *fn_inst = &side_real->e->functions[i];
                    WASMFunctionInstance *main_fn = wasm_lookup_function(
                        main_real, imp->u.function.field_name);
                    if (main_fn) {
                        fn_inst->import_module_inst = main_real;
                        fn_inst->import_func_inst = main_fn;
                    }
                }
            }
#endif
            /* (Old debug-only logging block removed — it was kept
             * around guarded by `if (0)` for ad-hoc rebind tracing;
             * stripped now that the rebind path is stable.) */
        }

        snprintf(tmpbuf, MAX_PACKET_SIZE, "OK:%x:", m->handle);
        write_packet(server, tmpbuf);
    }
    os_mutex_unlock(&tmpbuf_lock);
}

/*
 * qWasmUnloadSide:<handle-hex>
 *
 * Tear down a side module. Reply "OK" on success or
 * "ERR:bad-handle:..." if the handle is unknown.
 */
void
process_wasm_unload_side(WASMGDBServer *server, char *args)
{
    uint32 handle;
    WasmSideModule *m;

    os_mutex_lock(&tmpbuf_lock);
    handle = (uint32)strtoul(args, NULL, 16);
    m = find_side_module_by_handle(handle);
    if (!m) {
        emit_err_reply(server, "bad-handle", "no side module with that handle");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    destroy_side_module(m);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "OK");
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
process_wasm_call(WASMGDBServer *server, char *args)
{
    char *funcname_hex;
    char *argbytes_hex_start;
    char *first_colon;
    char *second_colon;
    char funcname[256];
    int32 name_len;
    WASMDebugInstance *debug_inst;
    WASMExecEnv *paused_env;
    wasm_module_inst_t module_inst;
    wasm_function_inst_t func;
    uint32 param_count, result_count;
    /* 64 params covers every realistic captured frame (Clay corpus
     * Cx117_many_locals tops out around 20). argv_cells is sized so
     * 64 i64 params still fit (each i64 takes two 32-bit cells). */
    wasm_valkind_t param_types[64], result_types[8];
    uint32 argv_cells[256];
    uint32 cell_idx = 0, i;
    uint32 param_bytes_expected = 0, result_bytes = 0;
    int32 arg_byte_count;
    wasm_exec_env_t call_env = NULL;
    bool ok;
    char ret_hex[256];
    uint32 side_handle = 0;
    WasmSideModule *side = NULL;

    /* Two forms (subplan #4 Parts A and G):
     *   1-segment-pair: qWasmCall:<funcname-hex>:<argbytes-hex>
     *                   target the paused main instance.
     *   2-segment-pair: qWasmCall:<handle-hex>:<funcname-hex>:<argbytes-hex>
     *                   target a side module previously committed via
     *                   qWasmLoadSide.
     *
     * Disambiguate by counting colons. The arg payload arrives with
     * the leading "WasmCall:" stripped by the caller; we get exactly
     * "<funcname>:<args>" or "<handle>:<funcname>:<args>".
     */
    first_colon = strchr(args, ':');
    second_colon = first_colon ? strchr(first_colon + 1, ':') : NULL;
    if (second_colon) {
        /* Three segments — side-module form. */
        *first_colon++ = '\0';
        side_handle = (uint32)strtoul(args, NULL, 16);
        funcname_hex = first_colon;
        *second_colon++ = '\0';
        argbytes_hex_start = second_colon;
    }
    else {
        /* Two segments — main-instance form. */
        funcname_hex = args;
        if (first_colon) {
            *first_colon++ = '\0';
            argbytes_hex_start = first_colon;
        }
        else {
            argbytes_hex_start = "";
        }
    }

    os_mutex_lock(&tmpbuf_lock);

    /* Decode function name (hex-encoded ASCII). */
    name_len = decode_hex_bytes(funcname_hex, (uint8 *)funcname,
                                (uint32)(sizeof(funcname) - 1));
    if (name_len < 0) {
        emit_err_reply(server, "bad-request", "malformed funcname-hex");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    funcname[name_len] = '\0';

    /* Resolve the target instance: side module if handle given,
     * otherwise the paused main instance. */
    if (side_handle != 0) {
        side = find_side_module_by_handle(side_handle);
        if (!side || !side->instance) {
            emit_err_reply(server, "bad-handle",
                           "qWasmCall: unknown side-module handle");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        module_inst = side->instance;
    }
    else {
        debug_inst = (WASMDebugInstance *)server->thread->debug_instance;
        paused_env = wasm_debug_instance_get_current_env(debug_inst);
        if (!paused_env) {
            emit_err_reply(server, "no-env",
                           "no paused exec_env on debug instance");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        module_inst = wasm_runtime_get_module_inst(paused_env);
        if (!module_inst) {
            emit_err_reply(server, "no-inst",
                           "no module instance on paused exec_env");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
    }

    /* Look up the function by name. Requires that the wasm module
     * was linked with --export-all (or the target function was
     * explicitly exported). */
    func = wasm_runtime_lookup_function(module_inst, funcname);
    if (!func) {
        char msg[320];
        snprintf(msg, sizeof(msg), "function '%s' not exported", funcname);
        emit_err_reply(server, "no-func", msg);
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    /* Read the signature so we know how many bytes to consume from
     * the argument blob and how many to write back. */
    param_count = wasm_func_get_param_count(func, module_inst);
    result_count = wasm_func_get_result_count(func, module_inst);
    if (param_count > sizeof(param_types) / sizeof(param_types[0])
        || result_count > sizeof(result_types) / sizeof(result_types[0])) {
        emit_err_reply(server, "too-many-args",
                       "function arity exceeds qWasmCall limit");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    if (param_count > 0)
        wasm_func_get_param_types(func, module_inst, param_types);
    if (result_count > 0)
        wasm_func_get_result_types(func, module_inst, result_types);

    for (i = 0; i < param_count; i++) {
        uint32 c = cells_for_kind(param_types[i]);
        param_bytes_expected += c * 4;
        cell_idx += c;
    }
    if (cell_idx > sizeof(argv_cells) / sizeof(argv_cells[0])) {
        emit_err_reply(server, "too-many-cells",
                       "function cell count exceeds qWasmCall limit");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    for (i = 0; i < result_count; i++) {
        result_bytes += cells_for_kind(result_types[i]) * 4;
    }

    /* argv_cells doubles as both input and output buffer. Decode
     * arg bytes straight into it; wasm uses little-endian, host is
     * also little-endian on every target we ship, so a raw memcpy
     * works. */
    memset(argv_cells, 0, sizeof(argv_cells));
    arg_byte_count = decode_hex_bytes(argbytes_hex_start, (uint8 *)argv_cells,
                                      (uint32)sizeof(argv_cells));
    if (arg_byte_count < 0) {
        emit_err_reply(server, "bad-request", "malformed argbytes-hex");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    if ((uint32)arg_byte_count != param_bytes_expected) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "arg-byte count mismatch: got %d, expected %u", arg_byte_count,
                 param_bytes_expected);
        emit_err_reply(server, "bad-request", msg);
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    /* Spin up a derived exec_env on a fresh wasm stack so the call
     * cannot disturb the paused frame. The 64 KiB is why an embedded
     * target needs pool headroom beyond the running program: see
     * Brick/working_with_nucleo_h7a3.md. */
    call_env = wasm_runtime_create_exec_env(module_inst, 64 * 1024);
    if (!call_env) {
        emit_err_reply(server, "no-env", "wasm_runtime_create_exec_env failed");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    /* Clear any prior exception on the module instance so we can
     * distinguish "this call trapped" from "an earlier call left
     * an exception lying around". */
    wasm_runtime_set_exception(module_inst, NULL);

    /* Part B2: install per-call stdout capture so wasi fd_write
     * during the inferior call routes into our buffer instead of
     * the host's stdout. Captured bytes go back in the OK/ERR
     * reply's <stdout-hex> field. */
    wasm_debug_stdout_capture_begin();

    ok = wasm_runtime_call_wasm(call_env, func, cell_idx, argv_cells);

    {
        const char *captured_stdout = NULL;
        uint32 captured_size = 0;
        char stdout_hex[2 * 4096 + 1]; /* up to 4 KiB of stdout per call */
        wasm_debug_stdout_capture_end(&captured_stdout, &captured_size);
        if (captured_size > 0) {
            uint32 cap = sizeof(stdout_hex) / 2 - 1;
            uint32 to_hex = captured_size < cap ? captured_size : cap;
            mem2hex((char *)captured_stdout, stdout_hex, (int32)to_hex);
        }
        else {
            stdout_hex[0] = '\0';
        }

        if (!ok) {
            /* Error path: trap-coded ERR with the captured stdout. */
            const char *exc = wasm_runtime_get_exception(module_inst);
            char exc_hex[512];
            int32 exc_len = exc ? (int32)strlen(exc) : 0;
            if (exc_len > (int32)(sizeof(exc_hex) / 2 - 1))
                exc_len = (int32)(sizeof(exc_hex) / 2 - 1);
            if (exc_len > 0)
                mem2hex((char *)exc, exc_hex, exc_len);
            else
                exc_hex[0] = '\0';
            snprintf(tmpbuf, MAX_PACKET_SIZE, "ERR:%s:%s:%s",
                     trap_code_from_exception(exc), exc_hex, stdout_hex);
            write_packet(server, tmpbuf);
            wasm_runtime_set_exception(module_inst, NULL);
            wasm_runtime_destroy_exec_env(call_env);
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }

        if (result_bytes > sizeof(ret_hex) / 2 - 1) {
            emit_err_reply(server, "too-large",
                           "result-bytes exceed reply cap");
            wasm_runtime_destroy_exec_env(call_env);
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }
        mem2hex((char *)argv_cells, ret_hex, (int32)result_bytes);
        snprintf(tmpbuf, MAX_PACKET_SIZE, "OK:%s:%s", ret_hex, stdout_hex);
        write_packet(server, tmpbuf);
    }

    wasm_runtime_destroy_exec_env(call_env);
    os_mutex_unlock(&tmpbuf_lock);
}

/* TODO: let server send an empty/error reply.
   Original issue: 4265
   Not tested yet, but it should work.
 */
static void
send_reply(WASMGDBServer *server, const char *err)
{
    if (!err || !*err)
        write_packet(server, "");
    else
        write_packet(server, err);
}

void
handle_general_query(WASMGDBServer *server, char *payload)
{
    const char *name;
    char *args;
    char triple[256];

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';
    name = payload;
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);

    if (!strcmp(name, "C")) {
        uint64 pid, tid;
        pid = wasm_debug_instance_get_pid(
            (WASMDebugInstance *)server->thread->debug_instance);
        tid = (uint64)(uintptr_t)wasm_debug_instance_get_tid(
            (WASMDebugInstance *)server->thread->debug_instance);

        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE, "QCp%" PRIx64 ".%" PRIx64 "", pid,
                 tid);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "Supported")) {
        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "qXfer:libraries:read+;PacketSize=%x;", MAX_PACKET_SIZE);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }

    if (!strcmp(name, "Xfer")) {
        name = args;

        if (!args) {
            LOG_ERROR("payload parse error during handle_general_query");
            send_reply(server, "");
            return;
        }

        args = strchr(args, ':');

        if (args) {
            *args++ = '\0';
            process_xfer(server, name, args);
        }
    }

    if (!strcmp(name, "HostInfo")) {
        mem2hex("wasm32-wamr-wasi-wasm", triple,
                strlen("wasm32-wamr-wasi-wasm"));

        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "vendor:wamr;ostype:wasi;arch:wasm32;"
                 "triple:%s;endian:little;ptrsize:4;",
                 triple);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "ModuleInfo")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "GetWorkingDir")) {
        /* No filesystem cwd on embedded targets (Zephyr/NuttX/FreeRTOS);
         * getcwd isn't part of their minimal libc. Silently emit an
         * empty reply on those, which the LLDB client treats as
         * "unknown" (same as the upstream-default `qSupported` skip). */
#if !defined(__ZEPHYR__) && !defined(BH_PLATFORM_NUTTX) \
    && !defined(BH_PLATFORM_FREERTOS)
        os_mutex_lock(&tmpbuf_lock);
        if (getcwd(tmpbuf, PATH_MAX))
            write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
#else
        write_packet(server, "");
#endif
    }
    if (!strcmp(name, "QueryGDBServer")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "VAttachOrWaitSupported")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "ProcessInfo")) {
        // Todo: process id parent-pid
        uint64 pid;
        pid = wasm_debug_instance_get_pid(
            (WASMDebugInstance *)server->thread->debug_instance);
        mem2hex("wasm32-wamr-wasi-wasm", triple,
                strlen("wasm32-wamr-wasi-wasm"));

        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "pid:%" PRIx64 ";parent-pid:%" PRIx64
                 ";vendor:wamr;ostype:wasi;arch:wasm32;"
                 "triple:%s;endian:little;ptrsize:4;",
                 pid, pid, triple);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "RegisterInfo0")) {
        os_mutex_lock(&tmpbuf_lock);
        snprintf(
            tmpbuf, MAX_PACKET_SIZE,
            "name:pc;alt-name:pc;bitsize:64;offset:0;encoding:uint;format:hex;"
            "set:General Purpose Registers;gcc:16;dwarf:16;generic:pc;");
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    else if (!strncmp(name, "RegisterInfo", strlen("RegisterInfo"))) {
        write_packet(server, "E45");
    }
    if (!strcmp(name, "StructuredDataPlugins")) {
        write_packet(server, "");
    }

    if (args && (!strcmp(name, "MemoryRegionInfo"))) {
        uint64 addr = strtoll(args, NULL, 16);
        WASMDebugMemoryInfo *mem_info = wasm_debug_instance_get_memregion(
            (WASMDebugInstance *)server->thread->debug_instance, addr);
        if (mem_info) {
            char name_buf[256];
            mem2hex(mem_info->name, name_buf, strlen(mem_info->name));

            os_mutex_lock(&tmpbuf_lock);
            snprintf(tmpbuf, MAX_PACKET_SIZE,
                     "start:%" PRIx64 ";size:%" PRIx64
                     ";permissions:%s;name:%s;",
                     (uint64)mem_info->start, mem_info->size,
                     mem_info->permisson, name_buf);
            write_packet(server, tmpbuf);
            os_mutex_unlock(&tmpbuf_lock);

            wasm_debug_instance_destroy_memregion(
                (WASMDebugInstance *)server->thread->debug_instance, mem_info);
        }
    }

    if (!strcmp(name, "WasmData")) {
        write_packet(server, "");
    }

    if (!strcmp(name, "WasmMem")) {
        write_packet(server, "");
    }

    if (!strcmp(name, "Symbol")) {
        write_packet(server, "");
    }

    if (args && (!strcmp(name, "WasmCallStack"))) {
        uint64 tid = strtoll(args, NULL, 16);
        uint64 buf[1024 / sizeof(uint64)];
        uint32 count = wasm_debug_instance_get_call_stack_pcs(
            (WASMDebugInstance *)server->thread->debug_instance,
            (korp_tid)(uintptr_t)tid, buf, 1024 / sizeof(uint64));

        if (count > 0) {
            os_mutex_lock(&tmpbuf_lock);
            mem2hex((char *)buf, tmpbuf, count * sizeof(uint64));
            write_packet(server, tmpbuf);
            os_mutex_unlock(&tmpbuf_lock);
        }
        else
            write_packet(server, "");
    }

    if (args && (!strcmp(name, "WasmCall"))) {
        process_wasm_call(server, args);
    }

    if (args && (!strcmp(name, "WasmLoadSide"))) {
        process_wasm_load_side(server, args);
    }

    if (args && (!strcmp(name, "WasmUnloadSide"))) {
        process_wasm_unload_side(server, args);
    }

    if (args && (!strcmp(name, "WasmLocal"))) {
        process_wasm_local(server, args);
    }

    if (args && (!strcmp(name, "WasmLocalSet"))) {
        process_wasm_local_set(server, args);
    }

    if (args && (!strcmp(name, "WasmGlobal"))) {
        process_wasm_global(server, args);
    }

    if (!strcmp(name, "Offsets")) {
        write_packet(server, "");
    }

    if (!strncmp(name, "ThreadStopInfo", strlen("ThreadStopInfo"))) {
        int32 prefix_len = strlen("ThreadStopInfo");
        uint64 tid_number = strtoll(name + prefix_len, NULL, 16);
        korp_tid tid = (korp_tid)(uintptr_t)tid_number;
        uint32 status;

        status = wasm_debug_instance_get_thread_status(
            server->thread->debug_instance, tid);

        send_thread_stop_status(server, status, tid);
    }

    if (!strcmp(name, "WatchpointSupportInfo")) {
        os_mutex_lock(&tmpbuf_lock);
        // Any uint32 is OK for the watchpoint support
        snprintf(tmpbuf, MAX_PACKET_SIZE, "num:32;");
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
}

void
send_thread_stop_status(WASMGDBServer *server, uint32 status, korp_tid tid)
{
    int32 len = 0;
    uint64 pc;
    korp_tid tids[20];
    char pc_string[17];
    uint32 tids_count, i = 0;
    uint32 gdb_status = status;
    WASMExecEnv *exec_env;
    const char *exception;

    if (status == 0) {
        os_mutex_lock(&tmpbuf_lock);
        (void)snprintf(tmpbuf, MAX_PACKET_SIZE, "W%02" PRIx32, status);
        send_reply(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    tids_count = wasm_debug_instance_get_tids(
        (WASMDebugInstance *)server->thread->debug_instance, tids, 20);
    pc = wasm_debug_instance_get_pc(
        (WASMDebugInstance *)server->thread->debug_instance);

    if (status == WAMR_SIG_SINGSTEP) {
        gdb_status = WAMR_SIG_TRAP;
    }

    os_mutex_lock(&tmpbuf_lock);
    // TODO: how name a wasm thread?
    len = snprintf(tmpbuf, MAX_PACKET_SIZE,
                   "T%02" PRIx32 "thread:%" PRIx64 ";name:%s;", gdb_status,
                   (uint64)(uintptr_t)tid, "nobody");
    if (len < 0 || len >= MAX_PACKET_SIZE) {
        send_reply(server, "E01");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    if (tids_count > 0) {
        int n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len, "threads:");
        if (n < 0 || n >= MAX_PACKET_SIZE - len) {
            send_reply(server, "E01");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }

        len += n;
        while (i < tids_count) {
            if (i == tids_count - 1) {
                n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                             "%" PRIx64 ";", (uint64)(uintptr_t)tids[i]);
            }
            else {
                n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                             "%" PRIx64 ",", (uint64)(uintptr_t)tids[i]);
            }

            if (n < 0 || n >= MAX_PACKET_SIZE - len) {
                send_reply(server, "E01");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }

            len += n;
            i++;
        }
    }
    mem2hex((void *)&pc, pc_string, 8);
    pc_string[8 * 2] = '\0';

    exec_env = wasm_debug_instance_get_current_env(
        (WASMDebugInstance *)server->thread->debug_instance);
    bh_assert(exec_env);

    exception =
        wasm_runtime_get_exception(wasm_runtime_get_module_inst(exec_env));
    if (exception) {
        /* When exception occurs, use reason:exception so the description can be
         * correctly processed by LLDB */
        uint32 exception_len = strlen(exception);
        int n =
            snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                     "thread-pcs:%" PRIx64 ";00:%s;reason:%s;description:", pc,
                     pc_string, "exception");
        if (n < 0 || n >= MAX_PACKET_SIZE - len) {
            send_reply(server, "E01");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }

        len += n;
        /* The description should be encoded as HEX */
        for (i = 0; i < exception_len; i++) {
            n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len, "%02x",
                         exception[i]);
            if (n < 0 || n >= MAX_PACKET_SIZE - len) {
                send_reply(server, "E01");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }

            len += n;
        }

        (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len, ";");
    }
    else {
        if (status == WAMR_SIG_TRAP) {
            (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                           "thread-pcs:%" PRIx64 ";00:%s;reason:%s;", pc,
                           pc_string, "breakpoint");
        }
        else if (status == WAMR_SIG_SINGSTEP) {
            (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                           "thread-pcs:%" PRIx64 ";00:%s;reason:%s;", pc,
                           pc_string, "trace");
        }
        else { /* status > 0 (== 0 is checked at the function beginning) */
            (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                           "thread-pcs:%" PRIx64 ";00:%s;reason:%s;", pc,
                           pc_string, "signal");
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_v_packet(WASMGDBServer *server, char *payload)
{
    const char *name;
    char *args;

    args = strchr(payload, ';');
    if (args)
        *args++ = '\0';
    name = payload;
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);

    if (!strcmp("Cont?", name))
        write_packet(server, "vCont;c;C;s;S;");

    if (!strcmp("Cont", name)) {
        if (args) {
            if (args[0] == 's' || args[0] == 'c') {
                char *numstring = strchr(args, ':');
                if (numstring) {
                    uint64 tid_number;
                    korp_tid tid;

                    *numstring++ = '\0';
                    tid_number = strtoll(numstring, NULL, 16);
                    tid = (korp_tid)(uintptr_t)tid_number;
                    wasm_debug_instance_set_cur_thread(
                        (WASMDebugInstance *)server->thread->debug_instance,
                        tid);

                    if (args[0] == 's') {
                        wasm_debug_instance_singlestep(
                            (WASMDebugInstance *)server->thread->debug_instance,
                            tid);
                    }
                    else {
                        wasm_debug_instance_continue(
                            (WASMDebugInstance *)
                                server->thread->debug_instance);
                    }
                }
            }
        }
    }
}

void
handle_threadstop_request(WASMGDBServer *server, char *payload)
{
    korp_tid tid;
    uint32 status;
    WASMDebugInstance *debug_inst =
        (WASMDebugInstance *)server->thread->debug_instance;
    bh_assert(debug_inst);

    /* According to
       https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#Packets, the "?"
       package should be sent when connection is first established to query the
       reason the target halted */
    bh_assert(debug_inst->current_state == DBG_LAUNCHING);

    /* Waiting for the stop event */
    os_mutex_lock(&debug_inst->wait_lock);
    while (!debug_inst->stopped_thread) {
        os_cond_wait(&debug_inst->wait_cond, &debug_inst->wait_lock);
    }
    os_mutex_unlock(&debug_inst->wait_lock);

    tid = debug_inst->stopped_thread->handle;
    status = (uint32)debug_inst->stopped_thread->current_status->signal_flag;

    wasm_debug_instance_set_cur_thread(debug_inst, tid);

    send_thread_stop_status(server, status, tid);

    debug_inst->current_state = APP_STOPPED;
    debug_inst->stopped_thread = NULL;
}

void
handle_set_current_thread(WASMGDBServer *server, char *payload)
{
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);
    if ('g' == *payload++) {
        uint64 tid = strtoll(payload, NULL, 16);
        if (tid > 0)
            wasm_debug_instance_set_cur_thread(
                (WASMDebugInstance *)server->thread->debug_instance,
                (korp_tid)(uintptr_t)tid);
    }
    write_packet(server, "OK");
}

void
handle_get_register(WASMGDBServer *server, char *payload)
{
    uint64 regdata;
    int32 i = strtol(payload, NULL, 16);

    if (i != 0) {
        send_reply(server, "E01");
        return;
    }
    regdata = wasm_debug_instance_get_pc(
        (WASMDebugInstance *)server->thread->debug_instance);

    os_mutex_lock(&tmpbuf_lock);
    mem2hex((void *)&regdata, tmpbuf, 8);
    tmpbuf[8 * 2] = '\0';
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_get_json_request(WASMGDBServer *server, char *payload)
{
    char *args;

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';
    write_packet(server, "");
}

void
handle_get_read_binary_memory(WASMGDBServer *server, char *payload)
{
    write_packet(server, "");
}

void
handle_get_read_memory(WASMGDBServer *server, char *payload)
{
    uint64 maddr, mlen;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "");
    if (sscanf(payload, "%" SCNx64 ",%" SCNx64, &maddr, &mlen) == 2) {
        char *buff;

        if (mlen * 2 > MAX_PACKET_SIZE) {
            LOG_ERROR("Buffer overflow!");
            mlen = MAX_PACKET_SIZE / 2;
        }

        buff = wasm_runtime_malloc(mlen);
        if (buff) {
            ret = wasm_debug_instance_get_mem(
                (WASMDebugInstance *)server->thread->debug_instance, maddr,
                buff, &mlen);
            if (ret) {
                mem2hex(buff, tmpbuf, mlen);
            }
            wasm_runtime_free(buff);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_get_write_memory(WASMGDBServer *server, char *payload)
{
    size_t hex_len;
    int offset;
    int32 act_len;
    uint64 maddr, mlen;
    char *buff;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "");
    if (sscanf(payload, "%" SCNx64 ",%" SCNx64 ":%n", &maddr, &mlen, &offset)
        == 2) {
        payload += offset;
        hex_len = strlen(payload);
        act_len = hex_len / 2 < mlen ? hex_len / 2 : mlen;

        buff = wasm_runtime_malloc(act_len);
        if (buff) {
            hex2mem(payload, buff, act_len);
            ret = wasm_debug_instance_set_mem(
                (WASMDebugInstance *)server->thread->debug_instance, maddr,
                buff, &mlen);
            if (ret) {
                snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "OK");
            }
            wasm_runtime_free(buff);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_breakpoint_software_add(WASMGDBServer *server, uint64 addr,
                               size_t length)
{
    bool ret = wasm_debug_instance_add_breakpoint(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_breakpoint_software_remove(WASMGDBServer *server, uint64 addr,
                                  size_t length)
{
    bool ret = wasm_debug_instance_remove_breakpoint(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_write_add(WASMGDBServer *server, uint64 addr, size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_write_add(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_write_remove(WASMGDBServer *server, uint64 addr,
                               size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_write_remove(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_read_add(WASMGDBServer *server, uint64 addr, size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_read_add(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_read_remove(WASMGDBServer *server, uint64 addr, size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_read_remove(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_add_break(WASMGDBServer *server, char *payload)
{
    int arg_c;
    size_t type, length;
    uint64 addr;

    if ((arg_c = sscanf(payload, "%zx,%" SCNx64 ",%zx", &type, &addr, &length))
        != 3) {
        LOG_ERROR("Unsupported number of add break arguments %d", arg_c);
        send_reply(server, "");
        return;
    }

    switch (type) {
        case eBreakpointSoftware:
            handle_breakpoint_software_add(server, addr, length);
            break;
        case eWatchpointWrite:
            handle_watchpoint_write_add(server, addr, length);
            break;
        case eWatchpointRead:
            handle_watchpoint_read_add(server, addr, length);
            break;
        case eWatchpointReadWrite:
            handle_watchpoint_write_add(server, addr, length);
            handle_watchpoint_read_add(server, addr, length);
            break;
        default:
            LOG_ERROR("Unsupported breakpoint type %zu", type);
            write_packet(server, "");
            break;
    }
}

void
handle_remove_break(WASMGDBServer *server, char *payload)
{
    int arg_c;
    size_t type, length;
    uint64 addr;

    if ((arg_c = sscanf(payload, "%zx,%" SCNx64 ",%zx", &type, &addr, &length))
        != 3) {
        LOG_ERROR("Unsupported number of remove break arguments %d", arg_c);
        send_reply(server, "");
        return;
    }

    switch (type) {
        case eBreakpointSoftware:
            handle_breakpoint_software_remove(server, addr, length);
            break;
        case eWatchpointWrite:
            handle_watchpoint_write_remove(server, addr, length);
            break;
        case eWatchpointRead:
            handle_watchpoint_read_remove(server, addr, length);
            break;
        case eWatchpointReadWrite:
            handle_watchpoint_write_remove(server, addr, length);
            handle_watchpoint_read_remove(server, addr, length);
            break;
        default:
            LOG_ERROR("Unsupported breakpoint type %zu", type);
            write_packet(server, "");
            break;
    }
}

void
handle_continue_request(WASMGDBServer *server, char *payload)
{
    wasm_debug_instance_continue(
        (WASMDebugInstance *)server->thread->debug_instance);
}

void
handle_kill_request(WASMGDBServer *server, char *payload)
{
    wasm_debug_instance_kill(
        (WASMDebugInstance *)server->thread->debug_instance);
}

static void
handle_malloc(WASMGDBServer *server, char *payload)
{
    char *args;
    uint64 addr, size;
    int32 map_prot = MMAP_PROT_NONE;

    args = strstr(payload, ",");
    if (args) {
        *args++ = '\0';
    }
    else {
        LOG_ERROR("Payload parse error during handle malloc");
        send_reply(server, "");
        return;
    }

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "E03");

    size = strtoll(payload, NULL, 16);
    if (size > 0) {
        while (*args) {
            if (*args == 'r') {
                map_prot |= MMAP_PROT_READ;
            }
            if (*args == 'w') {
                map_prot |= MMAP_PROT_WRITE;
            }
            if (*args == 'x') {
                map_prot |= MMAP_PROT_EXEC;
            }
            args++;
        }
        addr = wasm_debug_instance_mmap(
            (WASMDebugInstance *)server->thread->debug_instance, size,
            map_prot);
        if (addr) {
            snprintf(tmpbuf, MAX_PACKET_SIZE, "%" PRIx64, addr);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

static void
handle_free(WASMGDBServer *server, char *payload)
{
    uint64 addr;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "E03");
    addr = strtoll(payload, NULL, 16);

    ret = wasm_debug_instance_ummap(
        (WASMDebugInstance *)server->thread->debug_instance, addr);
    if (ret) {
        snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "OK");
    }

    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle____request(WASMGDBServer *server, char *payload)
{
    char *args;

    if (payload[0] == 'M') {
        args = payload + 1;
        handle_malloc(server, args);
    }
    if (payload[0] == 'm') {
        args = payload + 1;
        handle_free(server, args);
    }
}

void
handle_detach_request(WASMGDBServer *server, char *payload)
{
    if (payload != NULL) {
        write_packet(server, "OK");
    }
    wasm_debug_instance_detach(
        (WASMDebugInstance *)server->thread->debug_instance);
}
