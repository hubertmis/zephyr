/*
 * Copyright (c) 2021 Nordic Semicondcutor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(ot_br, LOG_LEVEL_DBG);

#include <stdlib.h>

#include <zephyr.h>
#include <usb/usb_device.h>
#include <drivers/uart.h>

#include <net/net_core.h>
#include <net/net_if.h>
#include <net/net_pkt.h>

void main(void)
{
    printk("Hello, starting\n");
    printk("Is it working?\n");
}
