#include "tracewrap.h"
#include "cpu.h"
#include "qemu/log.h"
#include "exec/helper-proto.h"

#include "trace_helper.h"


/*
 * QEMUs helper.
 */

static uint32_t memop2size(MemOp op) {
    switch(op & MO_SIZE) {
    default:
        qemu_log("Memory access size not handled for MemOp: %d.\n", op);
        return 0;
    case MO_8:
        return 1;
    case MO_16:
        return 2;
    case MO_32:
        return 4;
    case MO_64:
        return 8;
    case MO_128:
        return 16;
    }
}

static const char *get_spr_name(uint32_t reg, uint32_t field, CPUPPCState *env) {
    const char *name = env->spr_cb[reg].name;
    if (name && field == NO_SPR_FIELD) {
        return name;
    }
    if (reg == SPR_XER) {
        switch (field) {
        default:
            return "not_handled_reg";
        case XER_SO:
            return "so";
        case XER_CA:
            return "ca";
        case XER_CA32:
            return "ca32";
        case XER_OV:
            return "ov";
        case XER_OV32:
            return "ov32";
        }
    }
    return "not_handled_reg";
}

void HELPER(trace_newframe)(uint64_t pc)
{
    qemu_trace_newframe(pc, 0);
}

void HELPER(trace_endframe)(CPUPPCState *state, uint64_t pc)
{
    qemu_trace_endframe(state, pc, PPC_INSN_SIZE);
}

void HELPER(trace_load_mem)(uint32_t addr, uint32_t val, MemOp op)
{
    qemu_log("LOAD at 0x%lx size: %d data: 0x%lx\n", (unsigned long) addr, memop2size(op), (unsigned long) val);
    OperandInfo *oi = load_store_mem(addr, 0, &val, memop2size(op));
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem)(uint32_t addr, uint32_t val, MemOp op)
{
    qemu_log("STORE at 0x%lx size: %d data: 0x%lx\n", (unsigned long) addr, memop2size(op), (unsigned long) val);
    OperandInfo *oi = load_store_mem(addr, 1, &val, memop2size(op));
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_mem_i64)(uint32_t addr, uint64_t val, MemOp op)
{
    qemu_log("LOAD at 0x%lx size: %d data: 0x%llx\n", (unsigned long) addr, memop2size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 0, &val, memop2size(op));
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem_i64)(uint32_t addr, uint64_t val, MemOp op)
{
    qemu_log("STORE at 0x%lx size: %d data: 0x%llx\n", (unsigned long) addr, memop2size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 1, &val, memop2size(op));
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_reg)(uint32_t reg, uint32_t val)
{
    OperandInfo *oi = load_store_reg(reg, val, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg)(uint32_t reg, uint32_t val)
{
    OperandInfo *oi = load_store_reg(reg, val, 1);
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_store_crf)(uint32_t crf, uint32_t val)
{
    OperandInfo *oi = load_store_crf(crf, val, 1);
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_crf)(uint32_t crf, uint32_t val)
{
    OperandInfo *oi = load_store_crf(crf, val, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_load_spr_reg)(CPUPPCState *env, uint32_t reg, uint32_t field, uint32_t val)
{
    const char *name = get_spr_name(reg, field, env);
    uint32_t size = sizeof(env->spr_cb[reg].default_value);
    OperandInfo *oi = load_store_spr_reg(name, val, size, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_spr_reg)(CPUPPCState *env, uint32_t reg, uint32_t field, uint32_t val)
{
    const char *name = get_spr_name(reg, field, env);
    uint32_t size = sizeof(env->spr_cb[reg].default_value);
    OperandInfo *oi = load_store_spr_reg(name, val, size, 1);
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_mode)(void *mode) { qemu_trace_set_mode(mode); }

#ifdef TARGET_PPC64
void HELPER(trace_load_reg64)(uint32_t reg, uint64_t val)
{
    OperandInfo *oi = load_store_reg64(reg, val, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg64)(uint32_t reg, uint64_t val)
{
    OperandInfo *oi = load_store_reg64(reg, val, 1);
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_mem64)(uint64_t addr, uint64_t val, MemOp op)
{
    qemu_log("LOAD at 0x%llx size: %d data: 0x%llx\n", (unsigned long long) addr, memop2size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 0, &val, memop2size(op));
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem64)(uint64_t addr, uint64_t val, MemOp op)
{
    qemu_log("STORE at 0x%llx size: %d data: 0x%llx\n", (unsigned long long) addr, memop2size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 1, &val, memop2size(op));
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_spr_reg64)(CPUPPCState *env, uint32_t reg, uint32_t field, uint64_t val)
{
    const char *name = get_spr_name(reg, field, env);
    uint32_t size = sizeof(env->spr_cb[reg].default_value);
    OperandInfo *oi = load_store_spr_reg(name, val, size, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_spr_reg64)(CPUPPCState *env, uint32_t reg, uint32_t field, uint64_t val)
{
    const char *name = get_spr_name(reg, field, env);
    uint32_t size = sizeof(env->spr_cb[reg].default_value);
    OperandInfo *oi = load_store_spr_reg(name, val, size, 1);
    qemu_trace_add_operand(oi, 0x2);
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
 * \param ls If set to 0 the usage flag is set to "read". Otherwise the usage flag is set to "written".
 * \param data Data written to the register.
 * \param data_size Size of the data in bytes.
 * \return OperandInfo* Pointer to the operand for a BAP frame.
 */
static OperandInfo *build_load_store_reg_op(const char *name, int ls, const void *data, size_t data_size) {
    RegOperand * ro = g_new(RegOperand, 1);
    reg_operand__init(ro);
    ro->name = strdup(name);

    OperandInfoSpecific *ois = g_new(OperandInfoSpecific, 1);
    operand_info_specific__init(ois);
    ois->reg_operand = ro;

    OperandUsage *ou = g_new(OperandUsage, 1);
    operand_usage__init(ou);
    if (ls == 0) {
        ou->read = 1;
    } else {
        ou->written = 1;
    }
    OperandInfo *oi = g_new(OperandInfo, 1);
    operand_info__init(oi);
    oi->bit_length = 0;
    oi->operand_info_specific = ois;
    oi->operand_usage = ou;
    oi->value.len = data_size;
    oi->value.data = g_malloc(oi->value.len);
    memcpy(oi->value.data, data, data_size);

    return oi;
}

OperandInfo *load_store_mem(uint64_t addr, int ls, const void *data, size_t data_size) {
    MemOperand * mo = g_new(MemOperand, 1);
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
    memcpy(oi->value.data, data, data_size);
    return oi;
}

OperandInfo *load_store_reg(uint32_t reg, uint32_t val, int ls) {
    const char *name = ppc_gpr_reg_names[reg];
    return build_load_store_reg_op(name, ls, &val, sizeof(val));
}

OperandInfo *load_store_reg64(uint32_t reg, uint64_t val, int ls) {
    const char *name = ppc_gpr_reg_names[reg];
    return build_load_store_reg_op(name, ls, &val, sizeof(val));
}

OperandInfo *load_store_crf(uint32_t crf, uint64_t val, int ls) {
    const char *name = ppc_crf_names[crf];
    return build_load_store_reg_op(name, ls, &val, 1);
}

OperandInfo *load_store_spr_reg(const char *name, uint64_t val, uint32_t size, int ls) {
    return build_load_store_reg_op(name, ls, &val, size);
}