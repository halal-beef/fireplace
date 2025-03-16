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

#include <stdio.h>

#include <unicorn/unicorn.h>

#include <fireplace/core/macros.h>
#include <fireplace/soc/memmap.h>

/* TODO: Only 32-bit address space is mapped right now */
// From: https://github.com/exynos990-mainline/lk3rd/blob/dev/platform/exynos9830/mmu/mmu.c
struct memory_mapping exynos990_12gb_memory[] = {
	// We can't really map TZ memory
	// { 0x00000000, 0xBFFFFFFFF, UC_PROT_READ },

	/* Unknown - TT_DEVICE(?) */
	{ 0x02000000, 0x00200000, UC_PROT_READ  },
	/* Internal PERI block 1 */
	{ 0x03000000, 0x00200000, UC_PROT_READ  },
	/* Internal PERI block 2 */
	{ 0x04000000, 0x00200000, UC_PROT_READ  },
	/* SIREX Virtual iRAM */
	{ 0x06000000, 0x0A000000, UC_PROT_READ  },
	/* Public PERI block 1 */
	{ 0x10000000, 0x10000000, UC_PROT_ALL   },
	/* RAM block 1 */
	{ 0x80000000, 0x79800000, UC_PROT_ALL   },
	/* Unknown - TT_NONCACHEBLE(?) */
	{ 0xF9800000, 0x03C00000, UC_PROT_ALL  },
	/* RAM block 2 */
	{ 0xFD400000, 0x00500000, UC_PROT_ALL   },
	/* Unknown - TT_NONCACHEBLE(?) */
	{ 0xFD900000, 0x00200000, UC_PROT_ALL  },
	/* RAM block 3 */
	{ 0xFDB00000, 0x02500000, UC_PROT_ALL   },
	/* End of 32-bit address space. */
	{ 0x00000000, 0x00000000, UC_PROT_NONE  },
};

int memmap_soc(uc_engine *uc, enum board_memory_type board)
{
	struct memory_mapping map;
	int ret = 0;

	if (board == MEMORY_8GB)
	{
		printf("8GB boards are not supported yet!\n");
		return -1;
	}

	for (int i = 0; exynos990_12gb_memory[i].perms != UC_PROT_NONE; i++)
	{
		map = exynos990_12gb_memory[i];

		// TODO: Change this to 64-bit when mapping 64-bit address space!
		printf("Mapping memory: A: 0x%x L: 0x%x\n", map.base, map.size);

		ret = uc_mem_map(uc, map.base, map.size, map.perms);
		uc_handle_error("Failed to map memory!", ret);
	}

	return ret;
}