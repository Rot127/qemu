#include "tracewrap.h"

#include "trace_helper.h"

#ifdef BSWAP_NEEDED
static void memcpy_rev(void *dest, const void *src, size_t size) {
  if (size < 1) {
    return;
  }
  const char *s = src;
  char *d = dest;
  for (size_t i = 0, j = size - 1; i < size; --j, ++i) {
    d[i] = s[j];
  }
}
#endif

// Copies from genptr

const char * const hex_regnames[TOTAL_PER_THREAD_REGS] = {
   "r0", "r1",  "r2",  "r3",  "r4",   "r5",  "r6",  "r7",
   "r8", "r9",  "r10", "r11", "r12",  "r13", "r14", "r15",
  "r16", "r17", "r18", "r19", "r20",  "r21", "r22", "r23",
  "r24", "r25", "r26", "r27", "r28",  "r29", "r30", "r31",
  "sa0", "lc0", "sa1", "lc1", "p3_0", "c5",  "m0",  "m1",
  "usr", "pc",  "ugp", "gp",  "cs0",  "cs1", "c14", "c15",
  "c16", "c17", "c18", "c19", "pkt_cnt",  "insn_cnt", "hvx_cnt", "c23",
  "c24", "c25", "c26", "c27", "c28",  "c29", "c30", "c31",
};

static const char * const hexagon_prednames[] = {
  "p0", "p1", "p2", "p3"
};

/*
 * Build frames
 *
 * Functions to fill the actual frame data.
 */

/**
 * \brief Builds a new register load/store operand and returns it.
 *
 * \param name The register name.
 * \param ls If set to 0 the usage flag is set to "read". Otherwise the usage
 * flag is set to "written". \param data Data written to the register. \param
 * data_size Size of the data in bytes. \return OperandInfo* Pointer to the
 * operand for a BAP frame.
 */
// static OperandInfo *build_load_store_reg_op(const char *name, int ls,
//                                             const void *data,
//                                             size_t data_size) {
//   RegOperand *ro = g_new(RegOperand, 1);
//   reg_operand__init(ro);
//   ro->name = strdup(name);

//   OperandInfoSpecific *ois = g_new(OperandInfoSpecific, 1);
//   operand_info_specific__init(ois);
//   ois->reg_operand = ro;

//   OperandUsage *ou = g_new(OperandUsage, 1);
//   operand_usage__init(ou);
//   if (ls == 0) {
//     ou->read = 1;
//   } else {
//     ou->written = 1;
//   }
//   OperandInfo *oi = g_new(OperandInfo, 1);
//   operand_info__init(oi);
//   oi->bit_length = 0;
//   oi->operand_info_specific = ois;
//   oi->operand_usage = ou;
//   oi->value.len = data_size;
//   oi->value.data = g_malloc(oi->value.len);
//   memcpy(oi->value.data, data, data_size);

//   return oi;
// }

static OperandInfo *build_load_store_mem(uint64_t addr, int ls, const void *data,
                            size_t data_size) {
  MemOperand *mo = g_new(MemOperand, 1);
  mem_operand__init(mo);

  mo->address = addr;

  OperandInfoSpecific *ois = g_new(OperandInfoSpecific, 1);
  operand_info_specific__init(ois);
  ois->mem_operand = mo;

  OperandUsage *ou = g_new(OperandUsage, 1);
  operand_usage__init(ou);
  if (ls == 0) {
    ou->read = 1;
  } else {
    ou->written = 1;
  }
  OperandInfo *oi = g_new(OperandInfo, 1);
  operand_info__init(oi);
  oi->bit_length = data_size * 8;
  oi->operand_info_specific = ois;
  oi->operand_usage = ou;
  oi->value.len = data_size;
  oi->value.data = g_malloc(oi->value.len);
#ifdef BSWAP_NEEDED
  memcpy_rev(oi->value.data, data, data_size);
#else
  memcpy(oi->value.data, data, data_size);
#endif
  return oi;
}

/*
 * QEMUs helper.
 */

void HELPER(trace_newframe)(target_ulong addr) {
  qemu_log("TRACE FRAME BEGIN at 0x%x\n", addr);
  qemu_trace_newframe(addr, 0);
}
void HELPER(trace_endframe)(CPUHexagonState *state, target_ulong addr,
                            uint32_t pkt_size) {
  qemu_log("TRACE FRAME END at 0x%x size: %d\n", addr, pkt_size);
  qemu_trace_endframe(state, addr, pkt_size);
}

// Memory
// name, return type, address, val, width
void HELPER(trace_load_mem)(target_ulong addr, target_ulong val, uint32_t width) {
  qemu_log("TRACE \tLOAD MEM at 0x%x width: %d data: 0x%x\n", addr, width, val);
  OperandInfo *oi = build_load_store_mem(addr, 0, &val, width);
  qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem)(target_ulong addr, target_ulong val, uint32_t width) {
  qemu_log("TRACE \tSTORE MEM at 0x%x width: %d data: 0x%lx\n", addr, width,
           (unsigned long)val);
  OperandInfo *oi = build_load_store_mem(addr, 1, &val, width);
  qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_mem_64)(target_ulong addr, uint64_t val, uint32_t width) {
  qemu_log("TRACE \tLOAD MEM at 0x%x width: %d data: 0x%lx\n", addr, width, val);
  OperandInfo *oi = build_load_store_mem(addr, 0, &val, width);
  qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem_64)(target_ulong addr, uint64_t val, uint32_t width) {
  qemu_log("TRACE \tSTORE MEM at 0x%lx width: %d data: 0x%lx\n", (unsigned long)addr, width,
           (unsigned long)val);
  OperandInfo *oi = build_load_store_mem(addr, 1, &val, width);
  qemu_trace_add_operand(oi, 0x2);
}

// GPRs
// name, return type, reg, val, load_new
void HELPER(trace_load_reg)(uint32_t reg, uint32_t val) {
  qemu_log("TRACE \tLOAD REG %s Val: 0x%x\n", hexagon_regnames[reg], val);
  // OperandInfo *oi = build_load_store_reg_op(reg, val, 0, load_new);
  // qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_load_reg_new)(uint32_t reg, uint32_t val) {
  qemu_log("TRACE \tLOAD REG NEW %s Val: 0x%x\n", hexagon_regnames[reg], val);
  // OperandInfo *oi = build_load_store_reg_op(reg, val, 0, load_new);
  // qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg)(uint32_t reg, uint32_t val) {
  qemu_log("TRACE \tSTORE REG %s Val: 0x%x\n", hexagon_regnames[reg], val);
  // OperandInfo *oi = load_store_reg(reg, val, 1);
  // qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_reg_pair)(uint32_t reg, uint64_t val) {
  qemu_log("TRACE \tLOAD REG %s:%s Val: 0x%lx\n", hexagon_regnames[reg+1], &hexagon_regnames[reg][1], val);
  // OperandInfo *oi = build_load_store_reg_op(reg, val, 0, load_new);
  // qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_load_reg_pair_new)(uint32_t reg, uint64_t val) {
  qemu_log("TRACE \tLOAD REG NEW %s:%s Val: 0x%lx\n", hexagon_regnames[reg+1], &hexagon_regnames[reg][1], val);
  // OperandInfo *oi = build_load_store_reg_op(reg, val, 0, load_new);
  // qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg_pair)(uint32_t reg, uint64_t val) {
  qemu_log("TRACE \tSTORE REG %s:%s Val: 0x%lx\n", hexagon_regnames[reg+1], &hexagon_regnames[reg][1], val);
  // OperandInfo *oi = load_store_reg(reg, val, 1);
  // qemu_trace_add_operand(oi, 0x2);
}

// VRegs
// name, return type, vreg, val, load_new
void HELPER(trace_load_vreg)(uint32_t vreg, void *val) {
  qemu_log("TRACE \tLOAD VREG: %d Val: %p\n", vreg, val);
}

void HELPER(trace_load_vreg_new)(uint32_t vreg, void *val) {
  qemu_log("TRACE \tLOAD VREG NEW: %d Val: %p\n", vreg, val);
}

void HELPER(trace_store_vreg)(uint32_t vreg, void *val) {
  qemu_log("TRACE \tSTORE VREG %d Val: %p\n", vreg, val);
}

// Predicates
// name, return type, pred reg, val, load_new
void HELPER(trace_load_pred)(uint32_t pred, target_ulong val) {
  qemu_log("TRACE \tLOAD PRED %s Val: 0x%x\n", hexagon_prednames[pred], val);
}

void HELPER(trace_load_pred_new)(uint32_t pred, target_ulong val) {
  qemu_log("TRACE \tLOAD PRED NEW: %s Val: 0x%x\n", hexagon_prednames[pred], val);
}

void HELPER(trace_store_pred)(uint32_t pred, target_ulong val) {
  qemu_log("TRACE \tSTORE PRED: %s Val: 0x%x\n", hexagon_prednames[pred], val);
}

void HELPER(trace_load_vpred)(uint32_t vpred, void *val) {
  qemu_log("TRACE \tLOAD VPRED %d Val: %p\n", vpred, val);
}

void HELPER(trace_load_vpred_new)(uint32_t vpred, void *val) {
  qemu_log("TRACE \tLOAD VPRED NEW: %d Val: %p\n", vpred, val);
}

void HELPER(trace_store_vpred)(uint32_t vpred, void *val) {
  qemu_log("TRACE \tSTORE VPRED: %d Val: %p\n", vpred, val);
}
