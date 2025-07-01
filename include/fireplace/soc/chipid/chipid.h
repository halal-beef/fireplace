/*
 *   Copyright (c) 2025 Umer Uddin <umer.uddin@mentallysanemainliners.org>
 *
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

#ifndef FIREPLACE_CHIPID_H
#define FIREPLACE_CHIPID_H

#include <unicorn/unicorn.h>

#define CHIPID0_OFFSET				0x4
#define CHIPID1_OFFSET				0x8
#define CHIPID_REV_OFFSET			0x10

#define MAIN_REV_SHIFT				(20)
#define SUB_REV_SHIFT				(16)

int chipid_init(struct uc_struct*);
void chipid_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

#endif
