#pragma once

#include "frame_arch.h"
#include <stdint.h>

#if defined(TARGET_PPC64)
const uint64_t frame_arch = frame_arch_powerpc;
const uint64_t frame_mach = frame_mach_ppc64;
#else
const uint64_t frame_arch = frame_arch_powerpc;
const uint64_t frame_mach = frame_mach_ppc;
#endif

