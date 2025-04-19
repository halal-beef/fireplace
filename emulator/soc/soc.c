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
	uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0); // start = 1, end = 0 -> entire range
	return err;
}
