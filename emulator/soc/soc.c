/*
 *   Copyright (c) 2025 Igor Belwon <igor.belwon@mentallysanemainliners.org>

 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.

 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <unicorn/unicorn.h>

#include <fireplace/soc/peripherals.h>
#include <fireplace/soc/fb/fb.h>
#include <fireplace/soc/gpio/gpio_alive.h>
#include <fireplace/soc/uart/uart.h>
#include <fireplace/soc/usb/usb.h>

struct peripheral exynos990_peripherals[] = {
	{"uart", true, 0x10540000, 0x1000, uart_init, uart_hook},
	{"gpio_alive", true, 0x15850000, 0x1000, gpio_alive_init, gpio_alive_hook},
	//{"usb_phy", true, USB_PHY_BASE, 0x100, usb_phy_init, usb_phy_hook},
	//{"usb", true, USB_DWC_BASE, 0x200000, usb_init, usb_hook},
	// TODO: Platforms with 1080p displays
	{"framebuffer", true, FB_ADDRESS, FB_SIZE, fb_init, fb_hook},
	{"terminator", false, 0x0, 0x0, NULL, NULL}
};

int soc_peripheral_init_one(uc_engine *uc,
			    struct peripheral *peri)
{
	int err = 0;

	err = peri->peri_init(uc);

	if(peri->hook)
		err = uc_hook_add(uc, &peri->hh, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, peri->peri_hook,
				  peri, peri->addressBase,
				  peri->addressBase + peri->addressSize - 1);

	if(err)
		printf("Failed to initialize %s\n", peri->name);

	return err;
}

#define INITIAL_CAPACITY 1024

typedef struct {
    uint64_t *pcs;
    size_t count;
    size_t capacity;
} PCSet;

void pcset_init(PCSet *set) {
    set->pcs = malloc(INITIAL_CAPACITY * sizeof(uint64_t));
    set->count = 0;
    set->capacity = INITIAL_CAPACITY;
}

int pcset_contains(PCSet *set, uint64_t pc) {
    for (size_t i = 0; i < set->count; ++i) {
        if (set->pcs[i] == pc) {
            return 1;
        }
    }
    return 0;
}

void pcset_add(PCSet *set, uint64_t pc) {
    if (set->count >= set->capacity) {
        set->capacity *= 2;
        set->pcs = realloc(set->pcs, set->capacity * sizeof(uint64_t));
    }
    set->pcs[set->count++] = pc;
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    static PCSet pcset;
    static int initialized = 0;

    if (!initialized) {
        pcset_init(&pcset);
        initialized = 1;
    }

    uint64_t pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    if (!pcset_contains(&pcset, pc)) {
        printf("[+] PC = 0x%" PRIx64 "\n", pc);
        pcset_add(&pcset, pc);
    }
}

static bool mem_invalid_cb(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value, void *user_data) {
    switch (type) {
        case UC_MEM_READ_UNMAPPED:
            printf("[!] Invalid memory READ at 0x%" PRIx64 " (size: %d bytes)\n", address, size);
            break;
        case UC_MEM_WRITE_UNMAPPED:
            printf("[!] Invalid memory WRITE at 0x%" PRIx64 " (size: %d bytes, value: 0x%" PRIx64 ")\n", address, size, value);
            break;
        case UC_MEM_FETCH_UNMAPPED:
            printf("[!] Invalid memory FETCH (execution) at 0x%" PRIx64 "\n", address);
            break;
        default:
            return false; // unhandled
    }

    // Align the address to page size (0x1000), and map 0x1000 bytes
    uint64_t aligned_addr = address & ~0xFFF;
    uc_err err = uc_mem_map(uc, aligned_addr, 0x1000, UC_PROT_ALL);  // Allow R/W/X
    if (err != UC_ERR_OK) {
        printf("[!] Failed to map memory at 0x%" PRIx64 ": %s\n", aligned_addr, uc_strerror(err));
        return false;
    }

    printf("[+] Mapped new page at 0x%" PRIx64 "\n", aligned_addr);
    return true; // continue emulation
}

// NOP instruction
#define ARM64_NOP 0xd503201f

// Target instructions
#define TARGET_MSR 0xd5033f9f
#define TARGET_SMC 0xd4000003
#define WHATISTHIS 0xB2407FE4
#define TARGET_MOV_W0_0 0x00008052
#define TARGET_RET 0xC0035FD6

void hook_smc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t instr;

    // Read current instruction
    if (uc_mem_read(uc, address, &instr, sizeof(instr)) != UC_ERR_OK) {
        printf("Failed to read memory at 0x%" PRIx64 "\n", address);
        return;
    }

    // Check for MSR or SMC
    if (instr == TARGET_MSR || instr == TARGET_SMC) {
        printf("Intercepted target instruction at 0x%" PRIx64 ", patching to NOP\n", address);

        // Patch to NOP
        uint32_t nop = ARM64_NOP;
        uc_mem_write(uc, address, &nop, sizeof(nop));
    }

    if(instr == WHATISTHIS)
    {
	printf("detected junk at 0x%" PRIx64 ", patching...\n", address);
        uint32_t instr = TARGET_MOV_W0_0;
        uc_mem_write(uc, address, &instr, 4);
        instr = TARGET_RET;
        uc_mem_write(uc, address + 4, &instr, 4);
    }
}

int soc_peripherals_init(uc_engine *uc)
{
	int err = 0;

	for (int i = 0; exynos990_peripherals[i].addressBase != 0x0; i++)
	{
		printf("Initializing peripheral %s\nhooked: %i\n",
			exynos990_peripherals[i].name,
			exynos990_peripherals[i].hook);

		err = soc_peripheral_init_one(uc, &exynos990_peripherals[i]);
	}

	uc_hook trace;
//	uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0); // start = 1, end = 0 -> entire range
        uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_smc, NULL, 1, 0);
	uc_hook_add(uc, &trace, UC_HOOK_MEM_INVALID, (void*)mem_invalid_cb, NULL, 1, 0);
	return err;
}
