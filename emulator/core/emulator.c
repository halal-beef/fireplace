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
#include <string.h>
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

	// Patch abnormal boot case while true loop.
	if ((err = uc_mem_write(uc, 0xe801b970, "\x08\x00\x00\x14\x1f\x20\x03\xd5", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

	// Skip MUIC stuff
    if ((err = uc_mem_write(uc, 0xe801a568, "\xc0\x03\x5f\xd6", 4)) != UC_ERR_OK)
            printf("ERROR PATCHING infinite loop: %s\n", uc_strerror(err));

	// Patch Post Gear Change to return success, i cant be bothered emulating ufs THAT far.
	if ((err = uc_mem_write(uc, 0xe8003b38, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING Post Gear Change: %s\n", uc_strerror(err));

	// Patch USB Boot check to return false.
	if ((err = uc_mem_write(uc, 0xe8013180, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING USB Boot: %s\n", uc_strerror(err));

	// Patch ECDSA Sign checks to return success.
	if ((err = uc_mem_write(uc, 0xe80873d8, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING USB Boot: %s\n", uc_strerror(err));

	// Patch KEYSTORAGE Initialisation to return success.
	if ((err = uc_mem_write(uc, 0xe80131c0, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING KEYSTORAGE Init: %s\n", uc_strerror(err));

	// Patch SSP Initialisation to return success.
	if ((err = uc_mem_write(uc, 0xe80132a8, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING SSP Init: %s\n", uc_strerror(err));

	// Patch LDFW Initialisation to return success.
	if ((err = uc_mem_write(uc, 0xe8012e80, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING LDFW Init: %s\n", uc_strerror(err));

	// Patch SPayload Initialisation to return success.
	if ((err = uc_mem_write(uc, 0xe80135a0, "\x00\x00\x80\x52\xc0\x03\x5f\xd6", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING SPayload Init: %s\n", uc_strerror(err));

	if ((err = uc_mem_write(uc, 0xe8002538, "\x80\x00\x80\x52", 4)) != UC_ERR_OK)
		printf("ERROR PATCHING do_download arg: %s\n", uc_strerror(err));

	// NOP Some TRNG stuff.
	if ((err = uc_mem_write(uc, 0xe80182d8, "\x1f\x20\x03\xd5\x1f\x20\x03\xd5", 8)) != UC_ERR_OK)
		printf("ERROR PATCHING TRNG: %s\n", uc_strerror(err));

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

//	printf("Setting up T32 Fuse Magic.\n");
//	if ((err = uc_mem_write(uc, 0x80000000, "\xca\xcc\x26\x66", 4)) != UC_ERR_OK)
//		printf("T32 Fuse Magic Set Failed: %s\n", uc_strerror(err));


	/*printf("FORCING DOWNLOAD MODE VIA PMU SPOOF!\n");

	uint32_t val = (0x12345600 | 0x1);

        if ((err = uc_mem_write(uc, 0x15860000 + 0x80c, &val, 4)) != UC_ERR_OK)
                printf("ERROR: %s\n", uc_strerror(err));

	val = 0x4e0000;*/
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
