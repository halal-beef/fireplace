/*
 *   Copyright (c) 2026 Umer Uddin <umer.uddin@mentallysanemainliners.org>

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

#include <fireplace/soc/ufs/ufs.h>

uint32_t REG_UTP_TRANSFER_REQ_LIST_BASE_L = 0;
uint32_t REG_UTP_TRANSFER_REQ_LIST_BASE_H = 0;

uint32_t arg1, arg2, arg3;
uint32_t active_rx = 1, active_tx = 1;
bool uic_command_pending_completion = false;
bool utp_command_pending_completion = false;
bool uic_command_needs_pms = false;

#define UIC_CMD_DME_GET 1
#define UIC_CMD_DME_SET 2
#define UIC_CMD_DME_PEER_SET 4
#define UIC_CMD_DME_LINK_STARTUP 0x16

int ufs_init(struct uc_struct *uc_s)
{
	printf("= ufs_init\n");
	return 0;
}

void ufs_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    if(!uic_command_pending_completion && !utp_command_pending_completion)
    {
        uc_mem_write(uc, 0x13100020, "\x0\x0\x0\x0", 4);
    }
	switch (address)
    {
        case 0x13100020:
            if (uic_command_pending_completion)
            {
                // Complete with no errors
                if (uic_command_needs_pms) {
                    uint32_t hcs;
                    uc_mem_read(uc, 0x13100030, &hcs, 4);
                    hcs &= ~(0x7 << 8);
                    hcs |=  (0x1 << 8);
                    uc_mem_write(uc, 0x13100030, &hcs, 4);

                    uc_mem_write(uc, 0x13100020, "\x10\x04\x00\x00", 4);
                    uic_command_needs_pms = false;
                } else {
                    uc_mem_write(uc, 0x13100020, "\x00\x04\x00\x00", 4);
                }
            }

            if(utp_command_pending_completion)
            {
                uint32_t val = 1;
                uc_mem_write(uc, 0x13100020, &val, 4);
                utp_command_pending_completion = false;
            }
            break;
        case 0x13100090:
            printf("[UFS] UFS UIC_COMMAND Register Write: 0x%llx\n", value);
            switch (value)
            {
                case UIC_CMD_DME_PEER_SET:
                    printf("[UFS] DME PEER SET Command Issued\n");
                    uic_command_pending_completion = true;
                    break;
                case UIC_CMD_DME_LINK_STARTUP:
                    printf("[UFS] Link startup Command Issued!!!!!\n");
                    uic_command_pending_completion = true;
                    break;
                case UIC_CMD_DME_GET:
                    printf("[UFS] DME GET Command Issued\n");
                    switch(arg1)
                    {
                        case 0x1540 << 16:
                            printf("[UFS] Lane count requested, return 2.\n");
                            uc_mem_write(uc, 0x1310009c, "\x02\x00\x00\x00", 4);
                            uic_command_pending_completion = true;
                            break;
                        case 0x1587 << 16:
                            printf("[UFS] Max gear requested, return 4.\n");
                            uc_mem_write(uc, 0x1310009c, "\x04\x00\x00\x00", 4);
                            uic_command_pending_completion = true;
                            break;
                        case 0x1560 << 16:
                            printf("[UFS] active tx data lanes request, return %d.\n", active_tx);
                            uc_mem_write(uc, 0x1310009c, &active_tx, 4);
                            uic_command_pending_completion = true;
                            break;
                        case 0x1561 << 16:
                            printf("[UFS] connected tx data lanes request, return %d.\n", active_tx);
                            uc_mem_write(uc, 0x1310009c, &active_tx, 4);
                            active_tx = 2; // stupid hack
                            uic_command_pending_completion = true;
                            break;
                        case 0x1580 << 16:
                            printf("[UFS] active rx data lanes request, return %d.\n", active_rx);
                            uc_mem_write(uc, 0x1310009c, &active_rx, 4);
                            uic_command_pending_completion = true;
                            break;
                        case 0x1581 << 16:
                            printf("[UFS] connected rx data lanes request, return %d.\n", active_rx);
                            uc_mem_write(uc, 0x1310009c, &active_rx, 4);
                            active_rx = 2; // stupid hack
                            uic_command_pending_completion = true;
                            break;
                        case 0x1543 << 16:
                            printf("[UFS] weird clock req, return 1.\n");
                            uc_mem_write(uc, 0x1310009c, "\x01\x00\x00\x00", 4);
                            uic_command_pending_completion = true;
                            break;
                        default:
                            printf("[UFS] Unknown DME GET arg1: 0x%llx\n", arg1);
                            uic_command_pending_completion = true;
                            break;
                    }
                    break;
                case UIC_CMD_DME_SET:
                    printf("[UFS] DME SET Command Issued\n");
                    printf("[UFS] DME SET arg1: 0x%llx, arg2: 0x%llx, arg3: 0x%llx\n", arg1, arg2, arg3);
                    switch(arg1)
                    {
                        case 0x1571 << 16:
                            printf("[UFS] PMC Stuff\n");
                            uic_command_pending_completion = true;
                            uic_command_needs_pms = true;
                            break;
                    }
                    // I wont lie to you i cannot be arsed to implement the whole cal.
                    uic_command_pending_completion = true;
                    break;
                default:
                    printf("[UFS] Unknown UIC_COMMAND: 0x%llx\n", value);
                    break;
            }
            break;
        case 0x13100094:
            printf("[UFS] UFS UIC_ARG1 Register Write: 0x%llx\n", value);
            arg1 = value;
            break;
        case 0x13100098:
            printf("[UFS] UFS UIC_ARG2 Register Write: 0x%llx\n", value);
            arg2 = value;
            break;
        case 0x1310009c:
            printf("[UFS] UFS UIC_ARG3 Register Write: 0x%llx\n", value);
            arg3 = value;
            break;
        case 0x13101154:
        case 0x13101150:
            uc_mem_write(uc, 0x13101150, "\x0\x0\x0\x0", 4);
            uc_mem_write(uc, 0x13101154, "\x0\x0\x0\x0", 4);
        break;
            case 0x13100050:
            if (type == UC_MEM_WRITE)
            {
                printf("[UFS] REG_UTP_TRANSFER_REQ_LIST_BASE_L Access\n");
                REG_UTP_TRANSFER_REQ_LIST_BASE_L = value;
                printf("[UFS] REG_UTP_TRANSFER_REQ_LIST_BASE_L Value: 0x%x\n", value);
            }
            break;
        case 0x13100054:
            if (type == UC_MEM_WRITE)
            {
                printf("[UFS] REG_UTP_TRANSFER_REQ_LIST_BASE_H Access\n");
                REG_UTP_TRANSFER_REQ_LIST_BASE_H = value;
                printf("[UFS] REG_UTP_TRANSFER_REQ_LIST_BASE_H Value: 0x%x\n", value);
                printf("[UFS] REG_UTP_TRANSFER_REQ_LIST_BASE_H Value: 0x%x\n", REG_UTP_TRANSFER_REQ_LIST_BASE_H);
            }
            break;
        case 0x13100058:
            if (type == UC_MEM_WRITE && value) {
                printf("[UFS] Doorbell rung: 0x%llx\n", value);

            uint64_t utrd_addr = ((uint64_t)REG_UTP_TRANSFER_REQ_LIST_BASE_H << 32) | REG_UTP_TRANSFER_REQ_LIST_BASE_L;
            struct ufs_utrd utrd;

            uc_mem_read(uc, utrd_addr, &utrd, sizeof(utrd));

            printf("UTRD Dump:\n");
            printf("dw[0]: 0x%x\n", utrd.dw[0]);
            printf("dw[1]: 0x%x\n", utrd.dw[1]);
            printf("dw[2]: 0x%x\n", utrd.dw[2]);
            printf("dw[3]: 0x%x\n", utrd.dw[3]);
            printf("cmd_desc_addr_l: 0x%x\n", utrd.cmd_desc_addr_l);
            printf("cmd_desc_addr_h: 0x%x\n", utrd.cmd_desc_addr_h);
            printf("rsp_upiu_len: 0x%x\n", utrd.rsp_upiu_len);
            printf("rsp_upiu_off: 0x%x\n", utrd.rsp_upiu_off);
            printf("prdt_len: 0x%x\n", utrd.prdt_len);
            printf("prdt_off: 0x%x\n", utrd.prdt_off);

            if (utrd.dw[0] == 0x0)
            {
                printf("[UFS] NOP, exiting boot mode.\n");
            }
            else if (utrd.dw[0] == 0x01000000)
            {
                printf("[UFS] UFS Command UTP_REQ_DESC_INT_CMD.\n");
            }
            printf("[UFS] Set OCS Success\n");
            utrd.dw[2] = 0x0; // Set OCS to success
            uc_mem_write(uc, utrd_addr, &utrd, sizeof(utrd));

            utp_command_pending_completion = true;
            } else if (type == UC_MEM_READ && !utp_command_pending_completion) {
                uc_mem_write(uc, 0x13100058, "\x0\x0\x0\x0", 4);
            }
        break;
    }
}
