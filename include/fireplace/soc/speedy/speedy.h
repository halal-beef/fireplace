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

#ifndef FIREPLACE_SPEEDY_H
#define FIREPLACE_SPEEDY_H

#include <unicorn/unicorn.h>

/* SPEEDY Register MAP */
#define SPEEDY_CTRL			0x000
#define SPEEDY_FIFO_CTRL		0x004
#define SPEEDY_CMD			0x008
#define SPEEDY_INT_ENABLE		0x00C
#define SPEEDY_INT_STATUS		0x010
#define SPEEDY_FIFO_STATUS		0x030
#define SPEEDY_TX_DATA			0x034
#define SPEEDY_RX_DATA			0x038
#define SPEEDY_PACKET_GAP_TIME		0x044
#define SPEEDY_TIMEOUT_COUNT		0x048
#define SPEEDY_FIFO_DEBUG		0x100
#define SPEEDY_CTRL_STATUS		0x104

/* SPEEDY_CTRL Register bits */
#define SPEEDY_ENABLE			(1 << 0)
#define SPEEDY_TIMEOUT_CMD_DISABLE	(1 << 1)
#define SPEEDY_TIMEOUT_STANDBY_DISABLE	(1 << 2)
#define SPEEDY_TIMEOUT_DATA_DISABLE	(1 << 3)
#define SPEEDY_ALWAYS_PULLUP_EN		(1 << 7)
#define SPEEDY_DATA_WIDTH_8BIT		(0 << 8)
#define SPEEDY_REMOTE_RESET_REQ_EN	(1 << 30)
#define SPEEDY_SW_RST			(1 << 31)

/* SPEEDY_FIFO_CTRL Register bits */
#define SPEEDY_RX_TRIGGER_LEVEL(x)	((x) << 0)
#define SPEEDY_TX_TRIGGER_LEVEL(x)	((x) << 8)
#define SPEEDY_FIFO_DEBUG_INDEX		(0 << 24)
#define SPEEDY_FIFO_RESET		(1 << 31)

/* SPEEDY_CMD Register bits */
#define SPEEDY_BURST_LENGTH(x)	((x) << 0)
#define SPEEDY_BURST_FIXED		(0 << 5)
#define SPEEDY_BURST_INCR		(1 << 5)
#define SPEEDY_BURST_EXTENSION		(2 << 5)
#define SPEEDY_ADDRESS(x)	(((x) & 0xFFF) << 7)
#define SPEEDY_ACCESS_BURST		(0 << 19)
#define SPEEDY_ACCESS_RANDOM		(1 << 19)
#define SPEEDY_DIRECTION_READ		(0 << 20)
#define SPEEDY_DIRECTION_WRITE		(1 << 20)

/* SPEEDY_INT_ENABLE Register bits */
#define SPEEDY_TRANSFER_DONE_EN		(1 << 0)
#define SPEEDY_TIMEOUT_CMD_EN		(1 << 1)
#define SPEEDY_TIMEOUT_STANDBY_EN	(1 << 2)
#define SPEEDY_TIMEOUT_DATA_EN		(1 << 3)
#define SPEEDY_FIFO_TX_ALMOST_EMPTY_EN	(1 << 4)
#define SPEEDY_FIFO_RX_ALMOST_FULL_EN	(1 << 8)
#define SPEEDY_RX_FIFO_INT_TRAILER_EN	(1 << 9)
#define SPEEDY_RX_MODEBIT_ERR_EN	(1 << 16)
#define SPEEDY_RX_GLITCH_ERR_EN		(1 << 17)
#define SPEEDY_RX_ENDBIT_ERR_EN		(1 << 18)
#define SPEEDY_TX_LINE_BUSY_ERR_EN	(1 << 20)
#define SPEEDY_TX_STOPBIT_ERR_EN	(1 << 21)
#define SPEEDY_REMOTE_RESET_REQ		(1 << 31)

/* SPEEDY_INT_STATUS Register bits */
#define SPEEDY_TRANSFER_DONE		(1 << 0)
#define SPEEDY_TIMEOUT_CMD		(1 << 1)
#define SPEEDY_TIMEOUT_STANDBY		(1 << 2)
#define SPEEDY_TIMEOUT_DATA		(1 << 3)
#define SPEEDY_FIFO_TX_ALMOST_EMPTY	(1 << 4)
#define SPEEDY_FIFO_RX_ALMOST_FULL	(1 << 8)
#define SPEEDY_RX_FIFO_INT_TRAILER	(1 << 9)
#define SPEEDY_RX_MODEBIT_ERR		(1 << 16)
#define SPEEDY_RX_GLITCH_ERR		(1 << 17)
#define SPEEDY_RX_ENDBIT_ERR		(1 << 18)
#define SPEEDY_TX_LINE_BUSY_ERR		(1 << 20)
#define SPEEDY_TX_STOPBIT_ERR		(1 << 21)
#define SPEEDY_REMOTE_RESET_REQ_STAT	(1 << 31)

/* SPEEDY_FIFO_STATUS Register bits */
#define SPEEDY_VALID_DATA_CNT		(0 << 0)
#define SPEEDY_FIFO_FULL		(1 << 5)
#define SPEEDY_FIFO_EMPTY		(1 << 6)

/* SPEEDY_PACKET_GAP_TIME Register bits */
#define SPEEDY_PULL_EN_CNT		(0xF << 0)
#define SPEEDY_PACKET_GAP_TIME_CNT	(0 << 16)

/* SPEEDY_CTRL_STATUS Register bits */
#define SPEEDY_FSM_IDLE			(1 << 0)
#define SPEEDY_FSM_INIT			(1 << 1)
#define SPEEDY_FSM_TX_CMD		(1 << 2)
#define SPEEDY_FSM_STANDBY		(1 << 3)
#define SPEEDY_FSM_DATA			(1 << 4)
#define SPEEDY_FSM_TIMEOUT		(1 << 5)
#define SPEEDY_FSM_TRANS_DONE		(1 << 6)
#define SPEEDY_FSM_IO_RX_STAT_MASK	(3 << 7)
#define SPEEDY_FSM_IO_TX_IDLE		(1 << 9)
#define SPEEDY_FSM_IO_TX_GET_PACKET	(1 << 10)

#define ACCESS_BURST			0
#define ACCESS_RANDOM			1
#define DIRECTION_READ			0
#define DIRECTION_WRITE			1

int speedy_init(struct uc_struct*);
void speedy_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

#endif
