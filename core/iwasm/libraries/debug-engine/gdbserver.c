/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "gdbserver.h"
#include "gdb_transport.h"
#include "handler.h"
#include "packets.h"
#include "utils.h"

typedef void (*PacketHandler)(WASMGDBServer *server, char *payload);

struct packet_handler_elem {
    char request;
    PacketHandler handler;
};

#define DEL_HANDLER(r, h) [r] = { .request = r, .handler = h }

static const struct packet_handler_elem packet_handler_table[255] = {
    DEL_HANDLER('Q', handle_general_set),
    DEL_HANDLER('q', handle_general_query),
    DEL_HANDLER('v', handle_v_packet),
    DEL_HANDLER('?', handle_threadstop_request),
    DEL_HANDLER('H', handle_set_current_thread),
    DEL_HANDLER('p', handle_get_register),
    DEL_HANDLER('j', handle_get_json_request),
    DEL_HANDLER('m', handle_get_read_memory),
    DEL_HANDLER('M', handle_get_write_memory),
    DEL_HANDLER('x', handle_get_read_binary_memory),
    DEL_HANDLER('Z', handle_add_break),
    DEL_HANDLER('z', handle_remove_break),
    DEL_HANDLER('c', handle_continue_request),
    DEL_HANDLER('k', handle_kill_request),
    DEL_HANDLER('_', handle____request),
    DEL_HANDLER('D', handle_detach_request),
};

WASMGDBServer *
wasm_create_gdbserver(const char *host, int *port)
{
    bh_socket_t listen_fd = (bh_socket_t)-1;
    WASMGDBServer *server;

    bh_assert(port);

    if (!(server = wasm_runtime_malloc(sizeof(WASMGDBServer)))) {
        LOG_ERROR("wasm gdb server error: failed to allocate memory");
        return NULL;
    }

    memset(server, 0, sizeof(WASMGDBServer));

    if (!(server->receive_ctx =
              wasm_runtime_malloc(sizeof(rsp_recv_context_t)))) {
        LOG_ERROR("wasm gdb server error: failed to allocate memory");
        goto fail;
    }

    memset(server->receive_ctx, 0, sizeof(rsp_recv_context_t));

    /* If a custom transport is registered (e.g., the USB-CDC transport
     * the firmware installs at boot — see wamr_debug_usb.c),
     * skip TCP socket setup entirely. The transport handles all the
     * recv/send for this server through gdb_transport.c. Without this
     * bypass, gdbserver init fails on bare-metal targets with
     * "socket bind failed" because there's no networking stack. */
    if (wasm_gdbserver_get_transport() != NULL) {
        server->listen_fd = (bh_socket_t)-1;
        return server;
    }

    if (0 != os_socket_create(&listen_fd, true, true)) {
        LOG_ERROR("wasm gdb server error: create socket failed");
        goto fail;
    }

    if (0 != os_socket_bind(listen_fd, host, port)) {
        LOG_ERROR("wasm gdb server error: socket bind failed");
        goto fail;
    }

    LOG_WARNING("Debug server listening on %s:%" PRIu32 "\n", host, *port);
    server->listen_fd = listen_fd;

    return server;

fail:
    if (listen_fd >= 0) {
        os_socket_shutdown(listen_fd);
        os_socket_close(listen_fd);
    }
    if (server->receive_ctx)
        wasm_runtime_free(server->receive_ctx);
    if (server)
        wasm_runtime_free(server);
    return NULL;
}

bool
wasm_gdbserver_listen(WASMGDBServer *server)
{
    int32 ret;

    /* No socket to listen on when a custom transport is registered;
     * listen/accept are conceptual no-ops for UART (the host opens
     * the tty whenever it wants — accept happens implicitly the
     * first time recv sees data). */
    if (wasm_gdbserver_get_transport() != NULL) {
        return true;
    }

    ret = os_socket_listen(server->listen_fd, 1);
    if (ret != 0) {
        LOG_ERROR("wasm gdb server error: socket listen failed");
        goto fail;
    }

    LOG_VERBOSE("listen for gdb client");
    return true;

fail:
    os_socket_shutdown(server->listen_fd);
    os_socket_close(server->listen_fd);
    return false;
}

bool
wasm_gdbserver_accept(WASMGDBServer *server)
{

    bh_socket_t sockt_fd = (bh_socket_t)-1;

    /* Custom transport: delegate. The UART transport's `accept`
     * implementation typically returns immediately (the port is
     * always "open"); a TCP-over-USB-CDC transport would block on
     * the first incoming connection. */
    const gdb_transport_ops_t *t = wasm_gdbserver_get_transport();
    if (t != NULL) {
        if (t->accept && !t->accept(t->ctx)) {
            LOG_ERROR("wasm gdb server error: transport accept failed");
            return false;
        }
        server->socket_fd = (bh_socket_t)-1;
        server->noack = false;
        return true;
    }

    LOG_VERBOSE("waiting for gdb client to connect...");

    os_socket_accept(server->listen_fd, &sockt_fd, NULL, NULL);
    if (sockt_fd < 0) {
        LOG_ERROR("wasm gdb server error: socket accept failed");
        goto fail;
    }

    LOG_VERBOSE("accept gdb client");
    server->socket_fd = sockt_fd;
    server->noack = false;
    return true;

fail:
    os_socket_shutdown(server->listen_fd);
    os_socket_close(server->listen_fd);
    return false;
}

void
wasm_gdbserver_detach(WASMGDBServer *server)
{
    if (server->socket_fd > 0) {
        os_socket_shutdown(server->socket_fd);
        os_socket_close(server->socket_fd);
    }
}

void
wasm_close_gdbserver(WASMGDBServer *server)
{
    if (server->receive_ctx) {
        wasm_runtime_free(server->receive_ctx);
    }
    if (server->socket_fd > 0) {
        os_socket_shutdown(server->socket_fd);
        os_socket_close(server->socket_fd);
    }
    if (server->listen_fd > 0) {
        os_socket_shutdown(server->listen_fd);
        os_socket_close(server->listen_fd);
    }
}

static inline void
handle_packet(WASMGDBServer *server, char request, char *payload)
{
    if (packet_handler_table[(int)request].handler != NULL)
        packet_handler_table[(int)request].handler(server, payload);
}

static void
process_packet(WASMGDBServer *server)
{
    uint8 *inbuf = (uint8 *)server->receive_ctx->receive_buffer;
    char request;
    char *payload = NULL;

    request = inbuf[0];

    if (request == '\0') {
        LOG_VERBOSE("ignore empty request");
        return;
    }

    payload = (char *)&inbuf[1];

    LOG_VERBOSE("receive request:%c %s\n", request, payload);
    handle_packet(server, request, payload);
}

static inline void
push_byte(rsp_recv_context_t *ctx, unsigned char ch, bool checksum)
{
    if (ctx->receive_index >= sizeof(ctx->receive_buffer)) {
        LOG_ERROR("RSP message buffer overflow");
        bh_assert(false);
        return;
    }

    ctx->receive_buffer[ctx->receive_index++] = ch;

    if (checksum) {
        ctx->check_sum += ch;
    }
}

/**
 * The packet layout is:
 * 1. Normal packet:
 *   '$' + payload + '#' + checksum(2bytes)
 *                    ^
 *                    packetend
 * 2. Interrupt:
 *   0x03
 */

/* return:
 *  0: incomplete message received
 *  1: complete message received
 *  2: interrupt message received
 */
static int
on_rsp_byte_arrive(unsigned char ch, rsp_recv_context_t *ctx)
{
    if (ctx->phase == Phase_Idle) {
        ctx->receive_index = 0;
        ctx->check_sum = 0;

        if (ch == 0x03) {
            LOG_VERBOSE("Receive interrupt package");
            return 2;
        }
        else if (ch == '$') {
            ctx->phase = Phase_Payload;
        }

        return 0;
    }
    else if (ctx->phase == Phase_Payload) {
        if (ch == '#') {
            ctx->phase = Phase_Checksum;
            push_byte(ctx, ch, false);
        }
        else {
            push_byte(ctx, ch, true);
        }

        return 0;
    }
    else if (ctx->phase == Phase_Checksum) {
        ctx->size_in_phase++;
        push_byte(ctx, ch, false);

        if (ctx->size_in_phase == 2) {
            ctx->size_in_phase = 0;

            bh_assert(ctx->receive_index >= 3);

            if ((hex(ctx->receive_buffer[ctx->receive_index - 2]) << 4
                 | hex(ctx->receive_buffer[ctx->receive_index - 1]))
                != ctx->check_sum) {
                LOG_WARNING("RSP package checksum error, ignore it");
                ctx->phase = Phase_Idle;
                return 0;
            }
            else {
                /* Change # to \0 */
                ctx->receive_buffer[ctx->receive_index - 3] = '\0';
                ctx->phase = Phase_Idle;
                return 1;
            }
        }

        return 0;
    }

    /* Should never reach here */
    bh_assert(false);
    return 0;
}

bool
wasm_gdbserver_handle_packet(WASMGDBServer *server)
{
    int32 n;
    char buf[1024];

    /* When a custom transport is registered, route through it.
     * UART transports don't have a settimeout()-style knob; the
     * 1000 ms wait is part of the recv() contract instead. */
    const gdb_transport_ops_t *t = wasm_gdbserver_get_transport();
    if (t != NULL) {
        n = (int32)t->recv(t->ctx, buf, sizeof(buf), 1000);
        if (n == 0) {
            /* 0 means peer EOF — UART doesn't have that, but
             * fall through to the "no bytes" branch below. */
            return true;
        }
        if (n < 0) {
            /* Timeout / no bytes ready. */
            return true;
        }
        /* Fall through with `n > 0` bytes in `buf`. */
        goto rx_done;
    }

    if (os_socket_settimeout(server->socket_fd, 1000) != 0) {
        LOG_ERROR("Set socket recv timeout failed");
        return false;
    }

    n = os_socket_recv(server->socket_fd, buf, sizeof(buf));

    if (n == 0) {
        handle_detach_request(server, NULL);
        LOG_VERBOSE("Debugger disconnected, waiting for debugger reconnection");
        return true;
    }
    else if (n < 0) {
#if defined(BH_PLATFORM_WINDOWS)
        if (WSAGetLastError() == WSAETIMEDOUT)
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK)
#endif
        {
            /* No bytes arrived */
            return true;
        }
        else {
            LOG_ERROR("Socket receive error");
            return false;
        }
    }
    else {
rx_done:
    {
        int32 i, ret;

        for (i = 0; i < n; i++) {
            ret = on_rsp_byte_arrive(buf[i], server->receive_ctx);

            if (ret == 1) {
                if (!server->noack)
                    write_data_raw(server, (uint8 *)"+", 1);

                process_packet(server);
            }
            else if (ret == 2) {
                handle_interrupt(server);
            }
        }
    }
    }

    return true;
}
