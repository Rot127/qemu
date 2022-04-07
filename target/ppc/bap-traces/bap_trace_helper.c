
#include "qemu/osdep.h"

#include "cpu.h"
#include "tracewrap.h"
#include "qemu/log.h"
#include "exec/helper-proto.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"

#include "bap_trace_helper.h"

void ppc_bap_trace_newframe(uint32_t pc)
{
    qemu_trace_newframe(pc, 0);
}

void ppc_bap_trace_endframe(CPUPPCState *state, uint32_t pc)
{
    qemu_trace_endframe(state, pc, PPC_INSN_SIZE);
}


