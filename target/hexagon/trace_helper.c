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

void HELPER(trace_newframe)(target_ulong addr) { qemu_trace_newframe(addr, 0); }
void HELPER(trace_endframe)(CPUHexagonState *state, target_ulong addr,
                            uint32_t pkt_size) {
  qemu_trace_endframe(state, addr, pkt_size);
}

// Memory
// name, return type, address, val, width
void HELPER(trace_load_mem)(target_ulong addr, uint64_t val, uint32_t width) {
  qemu_log("LOAD at 0x%x width: %d data: 0x%lx\n", addr, width, val);
  OperandInfo *oi = build_load_store_mem(addr, 0, &val, width);
  qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem)(target_ulong addr, uint64_t val, uint32_t width) {
  qemu_log("STORE at 0x%lx width: %d data: 0x%lx\n", (unsigned long)addr, width,
           (unsigned long)val);
  OperandInfo *oi = build_load_store_mem(addr, 1, &val, width);
  qemu_trace_add_operand(oi, 0x2);
}

// GPRs
// name, return type, reg, val, is_tmp
void HELPER(trace_load_reg)(uint32_t reg, target_ulong val, uint32_t is_tmp) {
  qemu_log("LOAD REG %d Val: 0x%x TMP: %d\n", reg, val, is_tmp);
  // OperandInfo *oi = build_load_store_reg_op(reg, val, 0, is_tmp);
  // qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg)(uint32_t reg, target_ulong val, uint32_t is_tmp) {
  qemu_log("STORE REG %d Val: 0x%x TMP: %d\n", reg, val, is_tmp);
  // OperandInfo *oi = load_store_reg(reg, val, 1);
  // qemu_trace_add_operand(oi, 0x2);
}

// VRegs
// name, return type, vreg, val, is_tmp
void HELPER(trace_load_vreg)(uint32_t vreg, void *val, uint32_t is_tmp) {
  qemu_log("LOAD VREG %d Val: %p TMP: %d\n", vreg, val, is_tmp);
}

void HELPER(trace_store_vreg)(uint32_t vreg, void *val, uint32_t is_tmp) {
  qemu_log("STORE VREG %d Val: %p TMP: %d\n", vreg, val, is_tmp);
}

// Predicates
// name, return type, pred reg, val, is_tmp
void HELPER(trace_load_pred)(uint32_t pred, target_ulong val, uint32_t is_tmp) {
  qemu_log("LOAD PRED %d Val: 0x%x TMP: %d\n", pred, val, is_tmp);
}

void HELPER(trace_store_pred)(uint32_t pred, target_ulong val,
                              uint32_t is_tmp) {
  qemu_log("STORE PRED %d Val: 0x%x TMP: %d\n", pred, val, is_tmp);
}

void HELPER(trace_load_vpred)(uint32_t vpred, void *val, uint32_t is_tmp) {
  qemu_log("LOAD VPRED %d Val: %p TMP: %d\n", vpred, val, is_tmp);
}

void HELPER(trace_store_vpred)(uint32_t vpred, void *val, uint32_t is_tmp) {
  qemu_log("STORE VPRED %d Val: %p TMP: %d\n", vpred, val, is_tmp);
}

// special registers (USR etc.)
// name, return type, ctrl reg, reg field, value, is_tmp
void HELPER(trace_store_ctrl)(uint32_t creg, uint32_t field, target_ulong val,
                              uint32_t is_tmp) {
  qemu_log("STORE CTRL REG: %d FIELD: %d Val: 0x%x TMP: %d\n", creg, field, val, is_tmp);
}
void HELPER(trace_load_ctrl)(uint32_t creg, uint32_t field, target_ulong val,
                             uint32_t is_tmp) {
  qemu_log("LOAD CTRL REG: %d FIELD: %d Val: 0x%x TMP: %d\n", creg, field, val, is_tmp);
}
