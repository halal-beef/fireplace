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

struct ufs_utrd
{
  uint32_t dw[4];
  uint32_t cmd_desc_addr_l;
  uint32_t cmd_desc_addr_h;
  uint16_t rsp_upiu_len;
  uint16_t rsp_upiu_off;
  uint16_t prdt_len;
  uint16_t prdt_off;
};

struct ufs_upiu_header
{
  uint8_t type;
  uint8_t flags;
  uint8_t lun;
  uint8_t tag;
  uint8_t cmd_type;
  uint8_t function;
  uint8_t response;
  uint8_t status;
  uint8_t ehs_length;
  uint8_t device_info;
  uint16_t data_length;
};

struct ufs_upiu
{
  struct ufs_utrd utrd;
  uint8_t tsf[20];
  uint8_t data[1024 - 20 - sizeof(struct ufs_upiu_header)];
};

struct ufs_prdt
{
  uint32_t base_addr_l;
  uint32_t base_addr_h;
  uint32_t reserved;
  uint32_t size;
};

struct ufs_cmd_descriptor
{
  struct ufs_upiu command_upiu;
  struct ufs_upiu response_upiu;
  struct ufs_prdt prd_table[128];
};

int ufs_init(struct uc_struct*);
void ufs_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

#endif