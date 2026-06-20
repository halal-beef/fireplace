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

int ufs_init(struct uc_struct*);
void ufs_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

#endif