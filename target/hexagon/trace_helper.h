#ifndef TRACE_HELPER
#define TRACE_HELPER

#include "tracewrap.h"

OperandInfo *load_store_crf(uint32_t reg, uint64_t val, int ls);
OperandInfo *load_store_spr_reg(const char *name, uint64_t val, uint32_t size, int ls);

#endif /* TRACE_HELPER */
