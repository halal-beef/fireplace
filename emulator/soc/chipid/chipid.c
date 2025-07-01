/*
 *   Copyright (c) 2025 Umer Uddin <umer.uddin@mentallysanemainliners.org>

 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include <unicorn/unicorn.h>

#include <fireplace/soc/chipid/chipid.h>

int chipid_init(struct uc_struct *uc_s)
{
	uint32_t revision_information;

	/*
	 * These are a real group of ChipIDs taken from my secondary device.
	 */
	uint32_t chip_id[2] = {0xD0A4DC0, 0xB0C};

	printf("= chipid_init\n");
	uc_mem_write(uc_s, 0x10000000, "\xE9830000", 8);

	uc_mem_write(uc_s, 0x10000000 + CHIPID0_OFFSET, &chip_id[0], 4);
	uc_mem_write(uc_s, 0x10000000 + CHIPID1_OFFSET, &chip_id[1], 4);

	/*
	 * EVT 1.1 chip will be emulated here.
	 */
	revision_information |= (1 << MAIN_REV_SHIFT);
	revision_information |= (1 << SUB_REV_SHIFT);
	uc_mem_write(uc_s, 0x10000000 + CHIPID_REV_OFFSET, &revision_information, 4);

	return 0;
}

void chipid_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{

}
