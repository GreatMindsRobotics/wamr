/*
 * Local addition (Sculptor): the registry for the optional transport
 * hook declared in gdb_transport.h. Single global slot — only one
 * debug instance is alive at a time on the targets that need this
 * (bare-metal firmware, etc.).
 */
#include "gdb_transport.h"

static const gdb_transport_ops_t *g_transport = NULL;

void
wasm_gdbserver_set_transport(const gdb_transport_ops_t *ops)
{
    g_transport = ops;
}

const gdb_transport_ops_t *
wasm_gdbserver_get_transport(void)
{
    return g_transport;
}
