/*
 *   Copyright (c) 2025 Igor Belwon <igor.belwon@mentallysanemainliners.org>

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

#include <fireplace/soc/uart/uart.h>

char uart_buf[UART_BUF_SIZE] = "\x0";
pthread_mutex_t uart_lock = PTHREAD_MUTEX_INITIALIZER;
int count = 0;

atomic_int line = 0;

void incr_line()
{
	int atLine = atomic_load(&line);
	atLine++;
	atomic_store(&line, atLine);
}

void append(char *s, char c)
{
	int count = strlen(s);
	s[count] = c;
	s[count + 1] = '\0';

	if(c == '\n')
		incr_line();
}

int uart_init(struct uc_struct *uc_s)
{
	printf("= uart_init\n");
	uc_mem_write(uc_s, 0x10540020, "\x0", 4);
	return 0;
}

void uart_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	pthread_mutex_lock(&uart_lock);
	append(uart_buf, value);
	if(count == UART_BUF_SIZE)
	{
		memset(uart_buf, '\0', sizeof(uart_buf));
		count = 0;
	}
	printf("%c", value);
	pthread_mutex_unlock(&uart_lock);
}
