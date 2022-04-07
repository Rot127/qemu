#ifndef BAP_TRACE_HELPER
#define BAP_TRACE_HELPER

#include "qemu/osdep.h"
#include "cpu.h"

#define PPC_INSN_SIZE 4

void ppc_bap_trace_newframe(uint32_t pc);
void ppc_bap_trace_endframe(CPUPPCState *state, uint32_t pc);

#endif /* BAP_TRACE_HELPER */
