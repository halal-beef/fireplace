/*
 *   Copyright (c) 2025 Umer Uddin <umer.uddin@mentallysanemainliners.org>

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

#include <fireplace/soc/gpio/exynos_gpio.h>

void exynos_gpio_cfg_pin(uc_engine *uc, uint64_t bank_base, int gpio, int cfg)
{
    uint32_t value;
    uc_mem_read(uc, BANK_CON(bank_base), &value, sizeof(value));
    value &= ~CON_MASK(gpio);
    value |= CON_SFR(gpio, cfg);
    uc_mem_write(uc, BANK_CON(bank_base), &value, sizeof(value));
}

void exynos_gpio_direction_output(uc_engine *uc, uint64_t bank_base, int gpio, int en)
{
    uint32_t value;
    exynos_gpio_cfg_pin(uc, bank_base, gpio, GPIO_OUTPUT);
    uc_mem_read(uc, BANK_DAT(bank_base), &value, sizeof(value));
    value &= ~DAT_MASK(gpio);
    if (en)
        value |= DAT_SET(gpio);
    uc_mem_write(uc, BANK_DAT(bank_base), &value, sizeof(value));
}

void exynos_gpio_direction_input(uc_engine *uc, uint64_t bank_base, int gpio)
{
    exynos_gpio_cfg_pin(uc, bank_base, gpio, GPIO_INPUT);
}

void exynos_gpio_set_value(uc_engine *uc, uint64_t bank_base, int gpio, int en)
{
    uint32_t value;
    uc_mem_read(uc, BANK_DAT(bank_base), &value, sizeof(value));
    value &= ~DAT_MASK(gpio);
    if (en)
        value |= DAT_SET(gpio);
    uc_mem_write(uc, BANK_DAT(bank_base), &value, sizeof(value));
}

uint32_t exynos_gpio_get_value(uc_engine *uc, uint64_t bank_base, int gpio)
{
    uint32_t value;
    uc_mem_read(uc, BANK_DAT(bank_base), &value, sizeof(value));
    return !!(value & DAT_MASK(gpio));
}

void exynos_gpio_set_pull(uc_engine *uc, uint64_t bank_base, int gpio, int mode)
{
    uint32_t value;
    uc_mem_read(uc, BANK_PULL(bank_base), &value, sizeof(value));
    value &= ~PULL_MASK(gpio);
    switch (mode) {
    case GPIO_PULL_NONE:
    case GPIO_PULL_DOWN:
    case GPIO_PULL_UP:
        value |= PULL_MODE(gpio, mode);
        break;
    default:
        break;
    }
    uc_mem_write(uc, BANK_PULL(bank_base), &value, sizeof(value));
}

void exynos_gpio_set_drv(uc_engine *uc, uint64_t bank_base, int gpio, int mode)
{
    uint32_t value;
    uc_mem_read(uc, BANK_DRV(bank_base), &value, sizeof(value));
    value &= ~DRV_MASK(gpio);
    value |= DRV_SET(gpio, mode);
    uc_mem_write(uc, BANK_DRV(bank_base), &value, sizeof(value));
}

void exynos_gpio_set_rate(uc_engine *uc, uint64_t bank_base, int gpio, int mode)
{
    uint32_t value;
    uc_mem_read(uc, BANK_DRV(bank_base), &value, sizeof(value));
    value &= ~RATE_MASK(gpio);
    switch (mode) {
    case GPIO_DRV_FAST:
    case GPIO_DRV_SLOW:
        value |= RATE_SET(gpio);
        break;
    default:
        return;
    }
    uc_mem_write(uc, BANK_DRV(bank_base), &value, sizeof(value));
}