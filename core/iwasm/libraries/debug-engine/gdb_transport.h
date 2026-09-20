/*
 * Local addition (Sculptor): pluggable transport for the GDB-RSP
 * stub. WAMR's debug-engine assumes a TCP socket — fine on hosted
 * platforms but unworkable on bare-metal microcontroller targets
 * where there is no networking stack. A firmware can register an
 * alternative transport (e.g., a USB-CDC UART) before starting the
 * debug instance; gdbserver.c and packets.c route through it
 * instead of os_socket_* when one is registered.
 *
 * The default (no transport registered) is unchanged: TCP socket,
 * exactly as upstream.
 */
#ifndef _GDB_TRANSPORT_H
#define _GDB_TRANSPORT_H

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gdb_transport_ops {
    /* Block until a "client connects" (for UART, just becomes
     * ready/configured). Return true on success. */
    bool (*accept)(void *ctx);

    /* Read up to `len` bytes into `buf` with a `timeout_ms` upper
     * bound. Returns:
     *   > 0   number of bytes read
     *     0   peer disconnected / EOF
     *   < 0   timeout or error (caller treats as "no bytes ready")
     */
    int (*recv)(void *ctx, void *buf, size_t len, uint32_t timeout_ms);

    /* Write `len` bytes. Returns bytes written, or < 0 on error. */
    int (*send)(void *ctx, const void *buf, size_t len);

    /* Close / detach. May be called multiple times. */
    void (*close)(void *ctx);

    void *ctx;
} gdb_transport_ops_t;

/**
 * Register a custom transport. Pass NULL to revert to the default
 * TCP socket. Must be called before wasm_runtime_start_debug_instance.
 */
void wasm_gdbserver_set_transport(const gdb_transport_ops_t *ops);

/* Internal: return the registered transport, or NULL for default TCP. */
const gdb_transport_ops_t *wasm_gdbserver_get_transport(void);

#ifdef __cplusplus
}
#endif

#endif /* _GDB_TRANSPORT_H */
