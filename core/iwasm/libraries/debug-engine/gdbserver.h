/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _GDB_SERVER_H
#define _GDB_SERVER_H

#include "bh_platform.h"

#ifndef PACKET_BUF_SIZE
/* 32 KiB upstream default — fine on desktops but lethal on embedded
 * because WASMGDBServer embeds one (so its struct alloc fails when the
 * runtime heap has less than 32 KiB free after wasm instantiation).
 * Override via `-DPACKET_BUF_SIZE=...` for embedded targets; 4 KiB is
 * plenty for Sculptor's GDB-RSP traffic (qWasmCall replies cap out
 * around 1.5 KiB). */
#define PACKET_BUF_SIZE 0x8000
#endif

enum GDBStoppointType {
    eStoppointInvalid = -1,
    eBreakpointSoftware = 0,
    eBreakpointHardware,
    eWatchpointWrite,
    eWatchpointRead,
    eWatchpointReadWrite
};

typedef enum rsp_recv_phase_t {
    Phase_Idle,
    Phase_Payload,
    Phase_Checksum
} rsp_recv_phase_t;

/* Remote Serial Protocol Receive Context */
typedef struct rsp_recv_context_t {
    rsp_recv_phase_t phase;
    uint32 receive_index;
    uint32 size_in_phase;
    uint8 check_sum;
    /* The IW REPL's `qWasmLoadSide` packet carries hex-encoded wasm
     * bytes (subplan #4 Part G). A 4 KiB buffer holds up to ~2 KiB
     * of raw fragment per chunk after framing + hex overhead, which
     * keeps the number of chunks for a ~10 KiB fragment in single
     * digits over USB-CDC. Firmware can override via the
     * `DEBUG_RSP_RECV_BUFFER_SIZE` build macro if memory is tighter. */
#if defined(DEBUG_RSP_RECV_BUFFER_SIZE)
    char receive_buffer[DEBUG_RSP_RECV_BUFFER_SIZE];
#else
    char receive_buffer[4096];
#endif
} rsp_recv_context_t;

typedef struct WasmDebugPacket {
    unsigned char buf[PACKET_BUF_SIZE];
    uint32 size;
} WasmDebugPacket;

struct WASMDebugControlThread;
typedef struct WASMGDBServer {
    bh_socket_t listen_fd;
    bh_socket_t socket_fd;
    WasmDebugPacket pkt;
    bool noack;
    struct WASMDebugControlThread *thread;
    rsp_recv_context_t *receive_ctx;
} WASMGDBServer;

WASMGDBServer *
wasm_create_gdbserver(const char *host, int *port);

bool
wasm_gdbserver_listen(WASMGDBServer *server);

bool
wasm_gdbserver_accept(WASMGDBServer *server);

void
wasm_gdbserver_detach(WASMGDBServer *server);

void
wasm_close_gdbserver(WASMGDBServer *server);

bool
wasm_gdbserver_handle_packet(WASMGDBServer *server);
#endif
