/* main.c - OpenThread NCP */

/*
 * Copyright (c) 2020 Tridonic GmbH & Co KG
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

#define APP_BANNER "***** OpenThread NCP on Zephyr %s *****"

static const struct device *mux_dev;

////////// TEST UART_MUX ////////////////////

#include <drivers/console/uart_mux.h>

static void interrupt_handler(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);
    printk("Uart mux IRQ handler\n");

	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
        int len;
        unsigned char buffer[1500];

		if (!uart_irq_rx_ready(dev)) {
			continue;
		}

		while (len = uart_fifo_read(dev, buffer, sizeof(buffer))) {
            if (len > 0) {
                printk("Received buffer:");
                for (int i = 0; i < len; ++i) {
                    printk(" %02x", buffer[i]);
                }
                printk("\n");
            }
		}
	}
}

void mux_attach_cb(const struct device *mux, int dlci_address, bool connected, void *user_data)
{
    // Intentionally empty
}

void uart_mux_init(void)
{
    int r;
    const struct device *uart_dev = device_get_binding("UART_1");

	if (!uart_dev) {
		return;
	}

    mux_dev = uart_mux_alloc();


    r = uart_mux_attach(mux_dev, uart_dev, 1, mux_attach_cb, NULL);
    if (r) {
        return;
    }

	uart_irq_callback_set(mux_dev, interrupt_handler);

	/* Enable rx interrupts */
	uart_irq_rx_enable(mux_dev);
}

void main(void)
{
	LOG_INF(APP_BANNER, CONFIG_NET_SAMPLE_APPLICATION_VERSION);
    printk("Hello, starting\n");
    printk("Is it working?\n");

    uart_mux_init();
}
