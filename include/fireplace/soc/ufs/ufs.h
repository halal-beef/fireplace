/*
 *   Copyright (c) 2026 Umer Uddin <umer.uddin@mentallysanemainliners.org>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef FIREPLACE_UFS_H
#define FIREPLACE_UFS_H

#include <unicorn/unicorn.h>

#define ALIGNED_UPIU_SIZE	1024
#define SCSI_MAX_SG_SEGMENTS	128
#define DW_NUM_OF_TSF		20

#define UPIU_DATA_SIZE		(ALIGNED_UPIU_SIZE - \
		sizeof(uint8_t) * DW_NUM_OF_TSF - sizeof(struct ufs_upiu_header))


struct ufs_upiu_header {
	/* DW0 */
	uint8_t type;		/* [7]HD, [6]DD, [5:0]Transaction Type : UFS1.1 HD/DD should '0' */
	uint8_t flags;		/* Task Attribute : simple / ordered / head of queue */
	uint8_t lun;
	uint8_t tag;

	/* DW1 */
	uint8_t cmdtype;		/* Command Set Type */
	uint8_t function;		/* Query Function / Task Manag. Function */
	uint8_t response;
	uint8_t status;

	/* DW2 */
	uint8_t ehslength;		/* Total EHS length */
	uint8_t deviceinfo;		/* Device Information */
	uint16_t datalength;		/* Data Seqment Length (MSB|LSB) */
} __attribute__ ((__packed__));

struct ufs_upiu {
	struct ufs_upiu_header header;
	/* DW3 ~ DW7 */
	uint8_t tsf[DW_NUM_OF_TSF];		/* Transaction Specific Fields */
	uint8_t data[UPIU_DATA_SIZE];
} __attribute__ ((__packed__));

/*	Physical Region Descripton Table	*/
struct ufs_prdt {
	uint32_t base_addr;
	uint32_t upper_addr;
	uint32_t reserved;
	uint32_t size;		/* MSB(reserved) : LSB(data byte count) */
} __attribute__ ((__packed__));

/*	UTP Command Descriptor	*/
struct ufs_cmd_desc {
	struct ufs_upiu command_upiu;
	struct ufs_upiu response_upiu;
	struct ufs_prdt prd_table[SCSI_MAX_SG_SEGMENTS];
} __attribute__ ((__packed__));

/*	UTP Transfer Request Descriptor	*/
struct ufs_utrd {
	/* DW 0-3 */
	uint32_t dw[4];

	/* DW 4-5 */
	uint32_t cmd_desc_addr_l;
	uint32_t cmd_desc_addr_h;

	/* DW 6 */
	uint16_t rsp_upiu_len;
	uint16_t rsp_upiu_off;

	/* DW 7 */
	uint16_t prdt_len;
	uint16_t prdt_off;
} __attribute__ ((__packed__));

struct ufs_unit_desc {
	uint8_t bLength;		/* offset : 0x00 */
	uint8_t bDescriptorType;
	uint8_t bUnitIndex;
	uint8_t bLUEnable;
	uint8_t bBootLunID;

	uint8_t bLUWriteProtect;
	uint8_t bLUQueueDepth;
	uint8_t Reserved;
	uint8_t bMemoryType;		/* offset : 0x08 */
	uint8_t bDataReliability;

	uint8_t bLogicalBlockSize;
	uint32_t qLogicalBlockCount_h;
	uint32_t qLogicalBlockCount_l;
	uint32_t dEraseBlockSize;	/* offset : 0x13 */
	uint8_t bProvisioningType;
	uint32_t qPhyMemResourceCount_h;	/* offset : 0x18 */
	uint32_t qPhyMemResourceCount_l;
	uint16_t wContextCapabilities;	/* offset : 0x20 */
	uint8_t bLargeUnitSize_M1;
};

typedef struct {
    uint32_t last_lba;
    uint32_t block_size;
} lu_capacity_t;


static lu_capacity_t lu_capacities[8] = {
    { .last_lba = 31234048, .block_size = 4096 },
    { .last_lba = 1024, .block_size = 4096 },
    { .last_lba = 1024, .block_size = 4096 },
	{ .last_lba = 2048, .block_size = 4096 },
	{ .last_lba = 4096, .block_size = 4096 }
};

static struct ufs_unit_desc unit_descriptor[8] = {
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x00,
        .bLUEnable = 0x02,
        .bBootLunID = 0x00,
        .bLUWriteProtect = 0x00,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x00,
        .bDataReliability = 0x00,
        .bLogicalBlockSize = 0x0C,
        .qLogicalBlockCount_h = 0x01000000,
        .qLogicalBlockCount_l = 0x000098DC,
        .dEraseBlockSize = 0x02010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x0098DC01,
        .qPhyMemResourceCount_l = 0x10000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x01,
        .bLUEnable = 0x01,
        .bBootLunID = 0x01,
        .bLUWriteProtect = 0x01,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x03,
        .bDataReliability = 0x01,
        .bLogicalBlockSize = 0x0C,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 0x00000400,
        .dEraseBlockSize = 0x02010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00040000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x02,
        .bLUEnable = 0x01,
        .bBootLunID = 0x02,
        .bLUWriteProtect = 0x01,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x03,
        .bDataReliability = 0x01,
        .bLogicalBlockSize = 0x0C,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 0x00000400,
        .dEraseBlockSize = 0x02010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00040000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x03,
        .bLUEnable = 0x01,
        .bBootLunID = 0x00,
        .bLUWriteProtect = 0x01,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x00,
        .bDataReliability = 0x00,
        .bLogicalBlockSize = 0x0C,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 0x00000800,
        .dEraseBlockSize = 0x02010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00080000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x04,
        .bLUEnable = 0x01,
        .bBootLunID = 0x00,
        .bLUWriteProtect = 0x01,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x00,
        .bDataReliability = 0x00,
        .bLogicalBlockSize = 0x0C,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 4096,
        .dEraseBlockSize = 0x02010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00100000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x05,
        .bLUEnable = 0x00,
        .bBootLunID = 0x00,
        .bLUWriteProtect = 0x00,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x00,
        .bDataReliability = 0x00,
        .bLogicalBlockSize = 0x00,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 0x00000000,
        .dEraseBlockSize = 0x00010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00000000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x06,
        .bLUEnable = 0x00,
        .bBootLunID = 0x00,
        .bLUWriteProtect = 0x00,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x00,
        .bDataReliability = 0x00,
        .bLogicalBlockSize = 0x00,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 0x00000000,
        .dEraseBlockSize = 0x00010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00000000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
    {
        .bLength = 0x2D,
        .bDescriptorType = 0x02,
        .bUnitIndex = 0x07,
        .bLUEnable = 0x00,
        .bBootLunID = 0x00,
        .bLUWriteProtect = 0x00,
        .bLUQueueDepth = 0x00,
        .Reserved = 0x00,
        .bMemoryType = 0x00,
        .bDataReliability = 0x00,
        .bLogicalBlockSize = 0x00,
        .qLogicalBlockCount_h = 0x00000000,
        .qLogicalBlockCount_l = 0x00000000,
        .dEraseBlockSize = 0x00010000,
        .bProvisioningType = 0x00,
        .qPhyMemResourceCount_h = 0x00000000,
        .qPhyMemResourceCount_l = 0x00000000,
        .wContextCapabilities = 0x0000,
        .bLargeUnitSize_M1 = 0x00,
    },
};

int ufs_init(struct uc_struct*);
void ufs_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

#endif