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
#include <fireplace/soc/chipid/chipid.h>
#include <fireplace/soc/fb/fb.h>
#include <fireplace/soc/gpio/gpio_alive.h>
#include <fireplace/soc/uart/uart.h>
#include <fireplace/soc/usb/usb.h>
#include <fireplace/soc/ufs/ufs.h>

#include <string.h>
#include <ctype.h>

struct peripheral exynos990_peripherals[] = {
	{"chipid", true, 0x10000000, 0x1000, chipid_init, chipid_hook},
	{"uart", true, 0x10540000, 0x1000, uart_init, uart_hook},
	{"gpio_alive", true, 0x15850000, 0x1000, gpio_alive_init, gpio_alive_hook},
	//{"usb_phy", true, USB_PHY_BASE, 0x100, usb_phy_init, usb_phy_hook},
	//{"usb", true, USB_DWC_BASE, 0x200000, usb_init, usb_hook},
	// TODO: Platforms with 1080p displays
    {"ufs", true, 0x13100000, 0x80000, ufs_init, ufs_hook},
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
bool ready_to_trace = false;
void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    if(ready_to_trace)
    {
        uint64_t lr;
        uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
        printf("[HOOK] Executing instruction at 0x%llx, lr = 0x%llx\n", address, lr);
    }
}

static bool mem_invalid_cb(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value, void *user_data) {
    uint64_t pc, lr;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    printf("PC: 0x%llx, LR: 0x%llx\n", pc, lr);

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

/* Read a NUL-terminated string out of guest memory, byte by byte
 * (safe against unmapped pages causing a giant uc_mem_read failure). */
static void read_cstring(uc_engine *uc, uint64_t addr, char *buf, size_t bufsize)
{
    if (addr == 0) {
        snprintf(buf, bufsize, "(null)");
        return;
    }
    size_t i = 0;
    while (i < bufsize - 1) {
        uint8_t c;
        if (uc_mem_read(uc, addr + i, &c, 1) != UC_ERR_OK) {
            buf[i] = 0;
            snprintf(buf + i, bufsize - i, "<unmapped @0x%llx>", (unsigned long long)(addr + i));
            return;
        }
        if (c == 0) break;
        buf[i++] = (char)c;
    }
    buf[i] = 0;
}
 
/* Pull the next integer/pointer argument: x1..x7 first, then stack. */
static uint64_t next_arg(uc_engine *uc, uint64_t *x, int *argi, uint64_t sp, int *stack_idx)
{
    if (*argi <= 7) {
        return x[(*argi)++];
    }
    uint64_t v = 0;
    uc_mem_read(uc, sp + 8 * (*stack_idx), &v, 8);
    (*stack_idx)++;
    return v;
}
 
/* Format `fmt` using the register values in x[0..7] (x[0] is the fmt
 * pointer itself and is not consumed as an argument) and write the
 * result into out (size outsz). */
static void format_string(uc_engine *uc, const char *fmt, uint64_t *x,
                           uint64_t sp, char *out, size_t outsz)
{
    size_t out_pos = 0;
    int argi = 1;       /* x0 is the format string, args start at x1 */
    int stack_idx = 0;
 
    for (const char *p = fmt; *p && out_pos < outsz - 1; p++) {
        if (*p != '%') {
            out[out_pos++] = *p;
            continue;
        }
 
        const char *start = p;
        p++;
        if (*p == '%') { /* literal %% */
            out[out_pos++] = '%';
            continue;
        }
 
        while (*p && strchr("-+ #0", *p)) p++;          /* flags */
        while (*p && isdigit((unsigned char)*p)) p++;     /* width */
        if (*p == '.') { p++; while (*p && isdigit((unsigned char)*p)) p++; } /* precision */
 
        int length = 0; /* 0=int, 1=long, 2=long long */
        while (*p == 'l' || *p == 'h' || *p == 'z' || *p == 'j' || *p == 't') {
            if (*p == 'l') length++;
            p++;
        }
 
        char conv = *p;
        size_t speclen = (size_t)(p - start) + 1;
        char spec[32];
        if (speclen >= sizeof(spec)) speclen = sizeof(spec) - 1;
        memcpy(spec, start, speclen);
        spec[speclen] = 0;
 
        char piece[1024];
        switch (conv) {
            case 'd': case 'i': {
                uint64_t v = next_arg(uc, x, &argi, sp, &stack_idx);
                if (length >= 2)      snprintf(piece, sizeof(piece), spec, (long long)(int64_t)v);
                else if (length == 1) snprintf(piece, sizeof(piece), spec, (long)(int64_t)v);
                else                  snprintf(piece, sizeof(piece), spec, (int)(int32_t)v);
                break;
            }
            case 'u': case 'x': case 'X': case 'o': {
                uint64_t v = next_arg(uc, x, &argi, sp, &stack_idx);
                if (length >= 2)      snprintf(piece, sizeof(piece), spec, (unsigned long long)v);
                else if (length == 1) snprintf(piece, sizeof(piece), spec, (unsigned long)v);
                else                  snprintf(piece, sizeof(piece), spec, (unsigned int)v);
                break;
            }
            case 'p': {
                uint64_t v = next_arg(uc, x, &argi, sp, &stack_idx);
                snprintf(piece, sizeof(piece), "0x%llx", (unsigned long long)v);
                break;
            }
            case 'c': {
                uint64_t v = next_arg(uc, x, &argi, sp, &stack_idx);
                snprintf(piece, sizeof(piece), spec, (int)v);
                break;
            }
            case 's': {
                uint64_t v = next_arg(uc, x, &argi, sp, &stack_idx);
                char strbuf[512];
                read_cstring(uc, v, strbuf, sizeof(strbuf));
                snprintf(piece, sizeof(piece), spec, strbuf);
                break;
            }
            case 'f': case 'e': case 'g': case 'F': case 'E': case 'G': {
                /* Floating args live in v0-v7, not x[]. Can't resolve here. */
                next_arg(uc, x, &argi, sp, &stack_idx); /* keep x-index sane just in case */
                snprintf(piece, sizeof(piece), "<float:not-supported>");
                break;
            }
            default: {
                snprintf(piece, sizeof(piece), "%s", spec);
                break;
            }
        }
 
        size_t plen = strlen(piece);
        if (out_pos + plen >= outsz - 1) plen = outsz - 1 - out_pos;
        memcpy(out + out_pos, piece, plen);
        out_pos += plen;
 
        if (conv == 0) break;
    }
    out[out_pos] = 0;
}
 
void hook_print(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t x[8];
    uint64_t lr, sp;
 
    uc_reg_read(uc, UC_ARM64_REG_X0, &x[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &x[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &x[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &x[4]);
    uc_reg_read(uc, UC_ARM64_REG_X5, &x[5]);
    uc_reg_read(uc, UC_ARM64_REG_X6, &x[6]);
    uc_reg_read(uc, UC_ARM64_REG_X7, &x[7]);
 
    uc_reg_read(uc, UC_ARM64_REG_X30, &lr);
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
 
    char fmt[1024];
    uc_mem_read(uc, x[0], fmt, sizeof(fmt) - 1);
    fmt[sizeof(fmt) - 1] = 0;
 
    char formatted[4096];
    format_string(uc, fmt, x, sp, formatted, sizeof(formatted));
 
    printf(formatted);
 
    /* emulate return */
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_hardware_rng(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Hardware RNG called\n");
    uint64_t val_ptr, val_len, lr;

    uc_reg_read(uc, UC_ARM64_REG_X0, &val_ptr);
    uc_reg_read(uc, UC_ARM64_REG_X1, &val_len);
    uc_reg_read(uc, UC_ARM64_REG_X30, &lr);

    uint8_t buf[val_len];

    for (uint64_t i = 0; i < val_len; i++)
        buf[i] = rand() & 0xFF;

    uc_mem_write(uc, val_ptr, buf, val_len);

    uint64_t ret = 0;
    uc_reg_write(uc, UC_ARM64_REG_X0, &ret);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_return(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_revision(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t val = 22;
    uint64_t lr;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_mem_write(uc, 0xe8154008, &val, sizeof(val));
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_unlock_status(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    bool val = false;
    uint64_t val_ptr, lr, ret = 0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &val_ptr);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_mem_write(uc, val_ptr, &val, sizeof(val));
    uc_reg_write(uc, UC_ARM64_REG_X0, &ret);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
    printf("hook_unlock_status called, ptr to out_unlock: 0x%llx\n", val_ptr);
}

void hook_get_warranty_bit(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr, val = 1;

    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM64_REG_X0, &val);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_something_return_one(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr, val = 1;

    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM64_REG_X0, &val);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_something_return_zero(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr, val = 0;

    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM64_REG_X0, &val);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_hyp_calls(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr;
    uint64_t x[5];

    uc_reg_read(uc, UC_ARM64_REG_X0, &x[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &x[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &x[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &x[4]);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    printf("Hypervisor was attempted to be called with x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx, x4=0x%llx\n", x[0], x[1], x[2], x[3], x[4]);

    if(x[0] == 0xc6000010)
    {
        int val = 1;
        printf("H-ARX Plugin registration attempted.\n");
        uc_reg_write(uc, UC_ARM64_REG_X0, &val);
    }

    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_exynos_smc_calls(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr;
    uint64_t x[5];

    uc_reg_read(uc, UC_ARM64_REG_X0, &x[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &x[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &x[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &x[4]);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    printf("Exynos SMC was attempted to be called with x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx, x4=0x%llx\n", x[0], x[1], x[2], x[3], x[4]);
    if(x[0] == 0x82000480)
    {
        printf("Exynos SMC: SMC_CMD_HARX_INITIALIZATION, ret 0\n");
        uint64_t val = 0;
        uc_reg_write(uc, UC_ARM64_REG_X0, &val);
        ready_to_trace = false;
    }
    else if (x[0] == 0xc200101d)
    {
        printf("Exynos SMC: SMC Read VBMETA Pub key, ret 0\n");
        uint64_t val = 0;
        uc_reg_write(uc, UC_ARM64_REG_X0, &val);
        ready_to_trace = false;
    }
    else if (x[0] == 0xfffffffffffffed2 && x[1] == 0x0)
    {
        printf("Exynos SMC: Get SOC Info\n");
        uint64_t val = 0x66001000;
        uc_reg_write(uc, UC_ARM64_REG_X0, &val);
    }

    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_avb_pubkey_compare(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t lr, ptr_val;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM64_REG_X5, &ptr_val);

    printf("AVB Public Key Compare called\n");

    uint64_t val = 0; // Return 0 to indicate keys match
    uint8_t pubkey_comp_ret = 0;
    uc_mem_write(uc, ptr_val, &pubkey_comp_ret, sizeof(pubkey_comp_ret));
    uc_reg_write(uc, UC_ARM64_REG_X0, &val);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
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
	uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_print, NULL, 0xe80dee98, 0xe80dee98); // start = 1, end = 0 -> entire range
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_smc, NULL, 1, 0);
	uc_hook_add(uc, &trace, UC_HOOK_MEM_INVALID, (void*)mem_invalid_cb, NULL, 1, 0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_hardware_rng, NULL, 0xe8014390, 0xe8014390);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_return, NULL, 0xe80b8580, 0xe80b8580);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_return, NULL, 0xe8012f10, 0xe8012f10);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_return, NULL, 0xe8085050, 0xe8085050);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_return, NULL, 0xe80b8850, 0xe80b8850);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_return, NULL, 0xe8013f60, 0xe8013f60);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_return, NULL, 0xe80858b8, 0xe80858b8);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_revision, NULL, 0xe8001948, 0xe8001948);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_unlock_status, NULL, 0xe8027240, 0xe8027240);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_get_warranty_bit, NULL, 0xe80858a8, 0xe80858a8);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_one, NULL, 0xe808b480, 0xe808b480);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe80138e8, 0xe80138e8);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe8013de0, 0xe8013de0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe8014010, 0xe8014010);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe80140c8, 0xe80140c8);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe8014180, 0xe8014180);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe8014230, 0xe8014230);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe8013ea0, 0xe8013ea0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe80142e0, 0xe80142e0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_something_return_zero, NULL, 0xe80147b0, 0xe80147b0);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_hyp_calls, NULL, 0xe8001e58, 0xe8001e58);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_hyp_calls, NULL, 0xe80e8e30, 0xe80e8e30);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_exynos_smc_calls, NULL, 0xe8012e38, 0xe8012e38);
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_avb_pubkey_compare, NULL, 0xe80b4290, 0xe80b4290);
	return err;
}
