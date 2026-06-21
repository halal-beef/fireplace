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

            printf("[UFS] Set OCS Success\n");
            utrd.dw[2] = 0x0; // Set OCS to success
            uc_mem_write(uc, utrd_addr, &utrd, sizeof(utrd));

            uint64_t desc_addr = ((uint64_t)utrd.cmd_desc_addr_h << 32) | utrd.cmd_desc_addr_l;
            struct ufs_cmd_desc desc;
            uc_mem_read(uc, desc_addr, &desc, sizeof(desc));
            printf("[UFS] Command Descriptor Dump:\n");
            printf("Command UPIU Header:\n");
            printf("type: 0x%x\n", desc.command_upiu.header.type);
            printf("flags: 0x%x\n", desc.command_upiu.header.flags);
            printf("lun: 0x%x\n", desc.command_upiu.header.lun);
            printf("tag: 0x%x\n", desc.command_upiu.header.tag);
            printf("cmdtype: 0x%x\n", desc.command_upiu.header.cmdtype);
            printf("function: 0x%x\n", desc.command_upiu.header.function);
            printf("response: 0x%x\n", desc.command_upiu.header.response);
            printf("status: 0x%x\n", desc.command_upiu.header.status);
            printf("EHS Length: 0x%x\n", desc.command_upiu.header.ehslength);
            printf("Device Info: 0x%x\n", desc.command_upiu.header.deviceinfo);
            printf("Data Length: 0x%x\n", desc.command_upiu.header.datalength);
            // UFS_STD_READ_REQ
            if(desc.command_upiu.header.function == 0x1)
            {
                printf("UFS_STD_READ_REQ function\n");
                printf("[UFS] UFS Query Request\n");
                printf("[UFS] TFS Dump:\n");
                printf("Opcode: 0x%x\n", desc.command_upiu.tsf[0]);
                printf("IDN: 0x%x\n", desc.command_upiu.tsf[1]);
                printf("Index: 0x%x\n", desc.command_upiu.tsf[2]);
                printf("Selector: 0x%x\n", desc.command_upiu.tsf[3]);
                // Opcode UPIU_QUERY_OPCODE_READ_ATTR
                if(desc.command_upiu.tsf[0] == 0x3)
                {
                    // IDN
                    switch (desc.command_upiu.tsf[1])
                    {
                        case 0x0:
                            printf("[UFS] UFS Query Request for bootlun enable\n");

                            struct ufs_upiu *resp = &desc.response_upiu;
                            memset(resp, 0, sizeof(*resp));

                            resp->header.type = 0x36;
                            resp->header.flags = 0x00;
                            resp->header.lun = desc.command_upiu.header.lun;
                            resp->header.tag = desc.command_upiu.header.tag;
                            resp->header.cmdtype  = 0x00;
                            resp->header.function = desc.command_upiu.header.function;
                            resp->header.response = 0x00;
                            resp->header.status = 0x00;

                            resp->tsf[0] = desc.command_upiu.tsf[0];
                            resp->tsf[1] = desc.command_upiu.tsf[1];
                            resp->tsf[2] = desc.command_upiu.tsf[2];
                            resp->tsf[3] = desc.command_upiu.tsf[3];

                            resp->tsf[8]  = 0x00;
                            resp->tsf[9]  = 0x00;
                            resp->tsf[10] = 0x00;
                            resp->tsf[11] = 0x01;

                            uc_mem_write(uc, desc_addr, &desc, sizeof(desc));
                            break;
                        default:
                            printf("[UFS] Unknown UFS Query Request IDN: 0x%x\n", desc.command_upiu.tsf[1]);
                            break;
                    }
                }
                // UPIU_QUERY_OPCODE_READ_DESC
                else if (desc.command_upiu.tsf[0] == 1)
                {
                    printf("UPIU_QUERY_OPCODE_READ_DESC function\n");
                    switch (desc.command_upiu.tsf[1])
                    {
                        case 0x0:
                            printf("[UFS] UFS Query Request for device descriptor\n");
                            break;
                        case 0x1:
                            printf("[UFS] UFS Query Request for configuration descriptor\n");
                            break;
                        case 0x2:
                            printf("[UFS] UFS Query Request for unit descriptor\n");

                            struct ufs_upiu *resp = &desc.response_upiu;
                            uint32_t resp_data_len = sizeof(struct ufs_unit_desc);

                            memset(resp, 0, sizeof(*resp));

                            if (desc.command_upiu.tsf[2] >= 8) {
                                printf("[UFS] Unit descriptor index %d out of range\n", desc.command_upiu.tsf[2]);
                                resp->header.response = 0x01; 
                                break;
                            }
                            printf("[UFS] Reading Unit Descriptor for LU %d\n", desc.command_upiu.tsf[2]);
                            memcpy(resp->data, &unit_descriptor[desc.command_upiu.tsf[2]], sizeof(struct ufs_unit_desc));

                            resp->tsf[8] = (uint8_t)((resp_data_len >> 24) & 0xFF);
                            resp->tsf[9] = (uint8_t)((resp_data_len >> 16) & 0xFF);
                            resp->tsf[10] = (uint8_t)((resp_data_len >> 8) & 0xFF);
                            resp->tsf[11] = (uint8_t)(resp_data_len & 0xFF);
                            break;
                        case 0x4:
                            printf("[UFS] UFS Query Request for interconnect descriptor\n");
                            break;
                        case 0x5:
                            printf("[UFS] UFS Query Request for string descriptor\n");
                            break;
                        case 0x7:
                            printf("[UFS] UFS Query Request for geometry descriptor\n");
                            break;
                        case 0x8:
                            printf("[UFS] UFS Query Request for power descriptor\n");
                            break;
                        default:
                            printf("[UFS] Unknown UFS Query Request Descriptor: 0x%x\n", desc.command_upiu.tsf[1]);
                            break;
                    }
                }
            }
            else if (desc.command_upiu.header.function == 0)
            {
                printf("[UFS] Scsi command received, opcode: 0x%x\n", desc.command_upiu.tsf[4]);
                switch(desc.command_upiu.tsf[4])
                {
                    case 0:
                        printf("[UFS] NOP, exiting boot mode.\n");
                        break;

                    case 0x3:
                    {
                        printf("[UFS] REQUEST_SENSE command received\n");

                        uint8_t sense_data[18] = {0};
                        sense_data[0] = 0x70;
                        sense_data[2] = 0x00;
                        sense_data[7] = 0x0A;
                        sense_data[12] = 0x00;
                        sense_data[13] = 0x00;

                        uint64_t prdt_addr_rs = desc_addr + utrd.prdt_off;
                        struct ufs_prdt prdt_entry_rs;
                        uc_mem_read(uc, prdt_addr_rs, &prdt_entry_rs, sizeof(prdt_entry_rs));

                        uint64_t sense_buf_addr = ((uint64_t)prdt_entry_rs.upper_addr << 32) | prdt_entry_rs.base_addr;
                        uc_mem_write(uc, sense_buf_addr, sense_data, sizeof(sense_data));

                        struct ufs_upiu *resp = &desc.response_upiu;
                        memset(resp, 0, sizeof(*resp));
                        resp->header.type = 0x21;
                        resp->header.flags = 0x00;
                        resp->header.lun = desc.command_upiu.header.lun;
                        resp->header.tag = desc.command_upiu.header.tag;
                        resp->header.cmdtype  = 0x00;
                        resp->header.function = 0x00;
                        resp->header.response = 0x00;
                        resp->header.status = 0x00;
                        resp->header.datalength = sizeof(sense_data);

                        uc_mem_write(uc, desc_addr, &desc, sizeof(desc));
                        break;
                    }

                case 0x12: {
                    printf("[UFS] INQUIRY command received\n");

                    uint8_t inq_data[36] = {0};
                    inq_data[0] = 0x00;
                    inq_data[1] = 0x00;
                    inq_data[2] = 0x06;
                    inq_data[3] = 0x02;
                    inq_data[4] = 0x1F;
                    inq_data[5] = 0x00;
                    inq_data[6] = 0x00;
                    inq_data[7] = 0x00;

                    memcpy(&inq_data[8],  "HALAL   ", 8);
                    memcpy(&inq_data[16], "BEEF            ", 16);
                    memcpy(&inq_data[32], "1.00", 4);

                    uint64_t prdt_addr_inq = desc_addr + utrd.prdt_off;
                    struct ufs_prdt prdt_entry_inq;
                    uc_mem_read(uc, prdt_addr_inq, &prdt_entry_inq, sizeof(prdt_entry_inq));

                    uint64_t inq_buf_addr = ((uint64_t)prdt_entry_inq.upper_addr << 32) | prdt_entry_inq.base_addr;
                    uc_mem_write(uc, inq_buf_addr, inq_data, sizeof(inq_data));

                    struct ufs_upiu *resp = &desc.response_upiu;
                    memset(resp, 0, sizeof(*resp));
                    resp->header.type = 0x21;
                    resp->header.lun = desc.command_upiu.header.lun;
                    resp->header.tag = desc.command_upiu.header.tag;
                    resp->header.response = 0x00;
                    resp->header.status = 0x00;
                    resp->header.datalength = sizeof(inq_data);

                    uc_mem_write(uc, desc_addr, &desc, sizeof(desc));
                    break;
                }

                    case 0x25:
                    {
                        printf("[UFS] READ_CAPACITY command received for LU%d\n", desc.command_upiu.header.lun);
                        
                        uint32_t last_lba, block_size;
                        uint8_t lun = desc.command_upiu.header.lun;
                        uint8_t response_data[8];
                        uint64_t prdt_addr = desc_addr + utrd.prdt_off;
                        struct ufs_prdt prdt_entry;

                        if (lun < 8) {
                            last_lba = lu_capacities[lun].last_lba - 1;
                            block_size = lu_capacities[lun].block_size - 1;
                        } else {
                            last_lba = 0;
                            block_size = 0x1000;
                        }

                        printf("[UFS] LU%d: last_lba=%u, block_size=%u\n", lun, last_lba, block_size);

                        response_data[0] = (uint8_t)((last_lba >> 24) & 0xFF);
                        response_data[1] = (uint8_t)((last_lba >> 16) & 0xFF);
                        response_data[2] = (uint8_t)((last_lba >> 8) & 0xFF);
                        response_data[3] = (uint8_t)(last_lba & 0xFF);
                        response_data[4] = (uint8_t)((block_size >> 24) & 0xFF);
                        response_data[5] = (uint8_t)((block_size >> 16) & 0xFF);
                        response_data[6] = (uint8_t)((block_size >> 8) & 0xFF);
                        response_data[7] = (uint8_t)(block_size & 0xFF);

                        uc_mem_read(uc, prdt_addr, &prdt_entry, sizeof(prdt_entry));

                        uint64_t data_addr = ((uint64_t)prdt_entry.upper_addr << 32) | prdt_entry.base_addr;

                        uc_mem_write(uc, data_addr, response_data, 8);
                        
                        struct ufs_upiu *resp = &desc.response_upiu;
                        memset(resp, 0, sizeof(*resp));
                        resp->header.type = 0x21;
                        resp->header.flags = 0x00;
                        resp->header.lun = lun;
                        resp->header.tag = desc.command_upiu.header.tag;
                        resp->header.cmdtype  = 0x00;
                        resp->header.function = 0x00;
                        resp->header.response = 0x00;
                        resp->header.status = 0;
                        resp->header.datalength = 8;
                        
                        uc_mem_write(uc, desc_addr, &desc, sizeof(desc));
                        break;
                    }
                }
            }
            utp_command_pending_completion = true;
            } else if (type == UC_MEM_READ && !utp_command_pending_completion) {
                uc_mem_write(uc, 0x13100058, "\x0\x0\x0\x0", 4);
            }
        break;
    }
}
