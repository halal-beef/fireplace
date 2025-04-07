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
#include <fireplace/soc/speedy/speedy.h>
#include <fireplace/soc/uart/uart.h>
#include <fireplace/soc/usb/usb.h>

struct peripheral exynos990_peripherals[] = {
	{"uart", true, 0x10540000, 0x1000, uart_init, uart_hook},
	{"gpio_alive", true, 0x15850000, 0x1000, gpio_alive_init, gpio_alive_hook},
	{"speedy_0", true, 0x15940000, 0x1000, speedy_init, speedy_hook},
        {"speedy_1", true, 0x15950000, 0x1000, speedy_init, speedy_hook},
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

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t pc;

	uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
	printf("[+] PC = 0x%" PRIx64 "\n", pc);
}

static bool mem_invalid_cb(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value, void *user_data) {
    if (type == UC_MEM_READ_UNMAPPED) {
        printf("[!] Invalid memory read at 0x%" PRIx64 " (size: %d bytes)\n", address, size);

        // Optionally map a page so the emu can continue
        uc_mem_map(uc, address & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
        printf("[+] Mapped new page at 0x%" PRIx64 "\n", address & ~0xFFF);

        return true; // continue emulation!
    }

    return false;
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
	uc_hook_add(uc, &trace, UC_HOOK_MEM_INVALID, (void*)mem_invalid_cb, NULL, 1, 0);
	return err;
}
