#include "tracewrap.h"
#include "exec/helper-head.h"
#include "tcg/tcg-op.h"

#include "bap_trace_helper.h"

void HELPER(trace_newframe)(uint32_t pc)
{
    qemu_trace_newframe(pc, 0);
}

void HELPER(trace_endframe)(CPUPPCState *state, uint32_t pc)
{
    qemu_trace_endframe(state, pc, PPC_INSN_SIZE);
}


