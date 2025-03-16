/*
 *   Copyright (c) 2025 Igor Belwon <igor.belwon@mentallysanemainliners.org>
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

#include <stdio.h>

#include <unicorn/unicorn.h>

#include <fireplace/core/macros.h>

#define INT_BIN_PATH "~/fireplace/lk.bin"
#define INT_BIN_ADDR 0xF8800000
#define INT_BIN_SIZE 0x00F00000

static inline int emulator_init(void)
{
        uc_engine *uc;
        int err = 0;

        printf("== Emulator starting ==\n");

#if defined(INT_BIN_PATH)
        printf("Using hardcoded :[ binary path %s\n", INT_BIN_PATH);
#else
        printf("No binary path provided! Bailing out\n");
        return -1;
#endif

        /* We have all we need - setup unicorn context */
        err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
        if (err)
                uc_err_printf("Failed to initialize UC Engine!", err);

        /* TODO: Load binary to memory, run the emulator */

        return 0;
}

void* _emulator_init(void* dummy)
{
        emulator_init();
        return dummy;
}