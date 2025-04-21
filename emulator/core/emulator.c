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

#include <stdatomic.h>
#include <stdio.h>

#include <unicorn/unicorn.h>

#include <fireplace/core/emulator.h>
#include <fireplace/core/macros.h>
#include <fireplace/soc/memmap.h>
#include <fireplace/soc/soc.h>

#define INT_BIN_PATH "/home/umer/Downloads/lk.bin"
#define INT_BIN_ADDR 0xE8000000
#define INT_BIN_SIZE 0x00F00000

static inline void do_image_patches(uc_engine *uc)
{
	int err;
	printf("Patching LK image\n");

	// Patch msr at 0xe8012eec
	if ((err = uc_mem_write(uc, 0xe8012eec, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
		printf("ERROR PATCHING msr: %s\n", uc_strerror(err));

	// Spoof EL3
	if ((err = uc_mem_write(uc, 0xe80b8e8c, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
		printf("ERROR PATCHING FUN_e80b87b8: %s\n", uc_strerror(err));

	// Patch smc at 0xe8012ef0
	if ((err = uc_mem_write(uc, 0xe8012e38, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
		printf("ERROR PATCHING smc: %s\n", uc_strerror(err));

	// Patch smc at 0xe8012ef0
	if ((err = uc_mem_write(uc, 0xe8012ef0, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
		printf("ERROR PATCHING smc: %s\n", uc_strerror(err));

	// Patch bl/beq at 0xe801b970
	if ((err = uc_mem_write(uc, 0xe801b970, "\x08\x00\x00\x14\x1f\x20\x03\xd5", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

        // Patch loop at 0xe80295cc
        if ((err = uc_mem_write(uc, 0xe80295cc, "\x1f\x20\x03\xd5\x1f\x20\x03\xd5", 8)) != UC_ERR_OK)
                printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

	// Patch wait loop at 0xe8028b64
        if ((err = uc_mem_write(uc, 0xe8028b64, "\x1f\x10\x00\x71", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

        // Patch loop at 0xe802b21c
        if ((err = uc_mem_write(uc, 0xe802b21c, "\x1f\x10\x00\x71", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

        // Patch loop at 0xe8028960
        if ((err = uc_mem_write(uc, 0xe8028960, "\x1f\x10\x00\x71", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

	// Patch blkread at 0xe8030128
        if ((err = uc_mem_write(uc, 0xe8030128, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING blkread: %s\n", uc_strerror(err));

        if ((err = uc_mem_write(uc, 0xe8030144, "\xc0\x03\x5f\xd6", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING blkread: %s\n", uc_strerror(err));

        // Patch blkwrite at 0xe8030220
        if ((err = uc_mem_write(uc, 0xe8030220, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING blkread: %s\n", uc_strerror(err));

        if ((err = uc_mem_write(uc, 0xee803023c, "\xc0\x03\x5f\xd6", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING blkread: %s\n", uc_strerror(err));

	// BLKRead patch dont work i cant be bothered 0xe803557c
        if ((err = uc_mem_write(uc, 0xe803557c, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING blkread caller: %s\n", uc_strerror(err));

        // Patch loop at 0xe801319c
        if ((err = uc_mem_write(uc, 0xe801319c, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

	// Patch OTP_v20 Random number function at 0xe8014390
        if ((err = uc_mem_write(uc, 0xe8014390, "\x00\x00\x80\xd2\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
                printf("ERROR PATCHING OTP_v20 Random number function: %s\n", uc_strerror(err));

	// Patch WHAT IS THIS SMC CALL at 0xe8012f10
        if ((err = uc_mem_write(uc, 0xe8012f10, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
                printf("ERROR PATCHING WHAT IS THIS SMC CALL: %s\n", uc_strerror(err));

        // Patch OTP_v20 Model ID Read function at 0xe80159c4
        if ((err = uc_mem_write(uc, 0xe80159c4, "\x00\x00\x80\xd2\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
                printf("ERROR PATCHING OTP_v20 Model ID Read function: %s\n", uc_strerror(err));

        // Patch OTP_v20 USE_ROM_SEC_BOOT_KEY_READ at 0xe8014c8c
        if ((err = uc_mem_write(uc, 0xe8014c8c, "\x1f\x20\x03\xd5\x1f\x20\x03\xd5", 8)) != UC_ERR_OK)
                printf("ERROR PATCHING PART1 OF OTP_v20 USE_ROM_SEC_BOOT_KEY_READ: %s\n", uc_strerror(err));

        if ((err = uc_mem_write(uc, 0xe8014ca0, "\x1f\x20\x03\xd5\x00\x00\x80\x52\xc0\x03\x5f\xd6", 12)) != UC_ERR_OK)
                printf("ERROR PATCHING PART2 OF OTP_v20 USE_ROM_SEC_BOOT_KEY_READ: %s\n", uc_strerror(err));

	// Patch secureboot farts, i literally cannot be bothered at 0xe8002444
        if ((err = uc_mem_write(uc, 0xe8002444, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING SECUREBOOT FARTS: %s\n", uc_strerror(err));

	// Patch whatever the hell this is at 0xe806b4f8
        if ((err = uc_mem_write(uc, 0xe806b4f8, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING WHAT IS THIS: %s\n", uc_strerror(err));

        // Patch call to a random func at 0xe806b684
        if ((err = uc_mem_write(uc, 0xe806b684, "\x1f\x20\x03\xd5", 4)) != UC_ERR_OK)
                printf("ERROR PATCHING RANDOM FUNC CALL: %s\n", uc_strerror(err));

	// Spoof battery voltage
	printf("Spoofing battery voltage to 3.86v\n");
	// LMFAO
        if ((err = uc_mem_write(uc, 0xe80b91a0, "\x80\xe2\x81\x52\xc0\x03\x5f\xd6\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5", 32)) != UC_ERR_OK)
                printf("ERROR SPOOFING BATTERY VOLTAGE: %s\n", uc_strerror(err));

	// Spoof battery percentage
	printf("Spoofing battery percentage to 100%\n");
        // LMFAO  
        if ((err = uc_mem_write(uc, 0xe80b9180, "\x80\x0c\x80\x52\xc0\x03\x5f\xd6\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1f\x20\x03\xd5", 28)) != UC_ERR_OK)
                printf("ERROR SPOOFING BATTERY PERCENTAGE: %s\n", uc_strerror(err));

/*	printf("FORCING DOWNLOAD MODE VIA PMU SPOOF!\n");

	uint32_t val = (0x12345600 | 0x1);

        if ((err = uc_mem_write(uc, 0x15860000 + 0x80c, &val, 4)) != UC_ERR_OK)
                printf("ERROR: %\n", uc_strerror(err));

	val = 0x4e0000;

        if ((err = uc_mem_write(uc, 0x15860000 + 0x808, &val, 4)) != UC_ERR_OK)
                printf("ERROR: %\n", uc_strerror(err));
*/
}

/*
 * load_image functions:
 * Copyright (c) 2023, Ivaylo Ivanov <ivo.ivanov@null.net>
 * https://github.com/ivoszbg/LAEmu/blob/main/main.c
 * Modified lightly.
 */

static inline uc_err
load_image(uc_engine *uc, const char *file, uint64_t base, uint64_t *last)
{
	char buf[1024];
	FILE *f;
	long sz;
	uc_err err;
	uint64_t addr = base;

	printf("Opening file: %s\n", file);

	if (!(f = fopen(file, "r")))
		return UC_ERR_HANDLE;

	printf("Opened fine!\n", file);

	fseek(f, 0L, SEEK_END);
	sz = ftell(f);
	fseek(f, 0L, SEEK_SET);

	while (ftell(f) != sz)
	{
		size_t n = fread(buf, 1, 1024, f);
		*last = addr;
		if ((err = uc_mem_write(uc, addr, buf, n)) != UC_ERR_OK)
			return err;
		addr += n;
	}

	return err;
}

atomic_int sharedState = 0;

static inline int emulator_init(void)
{
	uc_engine *uc;
	uint64_t end;
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
	uc_handle_error("Failed to open UC engine!", err);

	if (memmap_soc(uc, MEMORY_12GB))
	{
		printf("Failed to map memory for SoC!\n");
		return -1;
	}

	err = load_image(uc, INT_BIN_PATH, INT_BIN_ADDR, &end);
	uc_handle_error("Failed to load the initial binary to memory!", err);

	do_image_patches(uc);

	/*
	 * Basic emulator setup is done. Now, init peripherals.
	 */
	err = soc_peripherals_init(uc);
	if (err)
	{
		printf("Failed to initialize peripherals!\n");
		return -1;
	}

	printf("=== All good! Starting emulator! ===\n");
	atomic_store(&sharedState, STATE_RUNNING);
	err = uc_emu_start(uc, INT_BIN_ADDR, end, 0, 10000000000);

	int pc;

	printf("\n------> fireplace exception: %s\n", uc_strerror(err));
	atomic_store(&sharedState, STATE_CRASHED);

	if (uc_reg_read(uc, UC_ARM64_REG_PC, &pc) != UC_ERR_OK)
	{
		printf("Failed to read PC register\n");
	}

	else
	{
		printf("= PC at 0x%x =\n", pc);
	}

	uc_close(uc);

	atomic_store(&sharedState, STATE_OFF);
	return 0;
}

void *_emulator_init(void *dummy)
{
	emulator_init();
	return dummy;
}
