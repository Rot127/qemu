#ifndef TRACE_HELPER
#define TRACE_HELPER

#include "tracewrap.h"
#include "qemu/osdep.h"

#define PPC_INSN_SIZE 4

#define TRACE_CRX_NAME_BASE 0
#define TRACE_GPR_NAME_BASE (4 * 8)
#define TRACE_GPR_H_NAME_BASE (TRACE_GPR_NAME_BASE + (10 * 3) + (22 * 4))
#define TRACE_SPECIAL_NAME_BASE (TRACE_GPR_H_NAME_BASE + (10 * 4) + (22 * 5))


const char *ppc_crf_reg_names[] = { "crf0", "crf1", "crf2", "crf3", "crf4", "crf5", "crf6", "crf7" };

const char *ppc_gpr_reg_names[] = { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
    "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22",
    "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31" };

/* Used by SPE implementation */
const char *ppc_gprh_reg_names[] = { "r0H", "r1H", "r2H", "r3H", "r4H", "r5H", "r6H", "r7H", "r8H",
    "r9H", "r10H", "r11H", "r12H", "r13H", "r14H", "r15H", "r16H", "r17H", "r18H", "r19H", "r20H",
    "r21H", "r22H", "r23H", "r24H", "r25H", "r26H", "r27H", "r28H", "r29H", "r30H", "r31H" };

/* Special registers. Currently not used. */
const char *ppc_not_used_reg_names[] = { "vs0", "vs1", "vs2", "vs3", "vs4", "vs5", "vs6", "vs7", "vs8", "vs9",
    "vs10", "vs11", "vs12", "vs13", "vs14", "vs15", "vs16", "vs17", "vs18", "vs19", "vs20", "vs21",
    "vs22", "vs23", "vs24", "vs25", "vs26", "vs27", "vs28", "vs29", "vs30", "vs31", "vs32", "vs33",
    "vs34", "vs35", "vs36", "vs37", "vs38", "vs39", "vs40", "vs41", "vs42", "vs43", "vs44", "vs45",
    "vs46", "vs47", "vs48", "vs49", "vs50", "vs51", "vs52", "vs53", "vs54", "vs55", "vs56", "vs57",
    "vs58", "vs59", "vs60", "vs61", "vs62", "vs63", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21",
    "f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31", "v0", "v1", "v2", "v3",
    "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17",
    "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
    "xer", "vrsave", "fpscr", "vscr", "cr",
    "lr", "ctr", "tar", "ppr32", "ppr", "dscr", "bescr", "ebbhr", "ebbrr", "lpcr", "hrmor", "lpidr",
    "pcr", "tir", "urmor", "smfctrl", "msr", "pvr", "pir", "pidr", "ctrl", "pspb", "rpr", "hashkey",
    "hashpkey", "sprg0", "sprg1", "sprg2", "sprg3", "hsprg0", "hsprg1", "usprg0", "usprg1", "srr0",
    "srr1", "hsrr0", "hsrr1", "usrr0", "usrr1", "asdr", "dar", "hdar", "dsisr", "hdsisr", "heir",
    "hmer", "hmeer", "fscr", "hfscr", "purr", "spurr", "dexcr", "hdexcr", "udexcr", "cfar", "mmcr0",
    "mmcr1", "mmcr2", "mmcra", "siar", "sdar", "sier", "sier2", "sier3", "mmcr3", "dpdes",
    NULL
};

OperandInfo *load_store_crf_reg(uint32_t reg, uint64_t val, int ls);

#endif /* TRACE_HELPER */
