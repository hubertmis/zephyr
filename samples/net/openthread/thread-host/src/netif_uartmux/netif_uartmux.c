/*
 * Copyright (c) 2021 Nordic Semicondcutor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/uart.h>
#include <drivers/console/uart_mux.h>

#include <net/net_if.h>
#include <net/dummy.h> // TODO: Replace with proper L2

#define INSTANCE 0
#define INIT_PRIO 96
#define BUFFER_SIZE 1500 // TODO: MTU + overhead?

#define DATA(dev) ((struct uartmux_netif_data * const)(dev)->data)

#define CFG(dev) ((const struct uartmux_netif_cfg * const)(dev)->config)

struct uartmux_netif_cfg {
    const char *uart_name;
};

struct uartmux_netif_data {
    struct net_if *iface;
    const struct device *mux_dev;

    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_len;
};

static const struct uartmux_netif_cfg cfg = {
    .uart_name = "UART_1",
};
static struct uartmux_netif_data data;

// TODO: Move sem and thread somehow to data?
K_SEM_DEFINE(rx_sem, 0, 1);

#define RX_STACK_SIZE 500
#define RX_PRIORITY 5

static void rx_entry_point(void *, void *, void *);

K_THREAD_STACK_DEFINE(rx_stack_area, RX_STACK_SIZE);
struct k_thread rx_thread_data;

K_THREAD_DEFINE(rx_thread, RX_STACK_SIZE, rx_entry_point,
        &data, NULL, NULL,
        RX_PRIORITY, 0, 0);


static int send(const struct device *dev, struct net_pkt *pkt)
{
    int len;
    struct uartmux_netif_data *data = DATA(dev);
    struct net_buf *buf = net_buf_frag_last(pkt->buffer);

    len = uart_fifo_fill(data->mux_dev, buf->data, buf->len);

    // TODO: Wait until UART TX is completed?
    net_pkt_unref(pkt);

    return len;
}

static void rx_entry_point(void *arg1, void *arg2, void *arg3)
{
    struct uartmux_netif_data *data = arg1;
    size_t len;
    struct net_pkt *pkt;

    while (1)
    {
        k_sem_take(&rx_sem, K_FOREVER);
        len = data->buffer_len;

        __ASSERT_NO_MSG(len <= CONFIG_NET_BUF_DATA_SIZE);

        // TODO: Use AF_UNSPEC here and update in proper L2
        pkt = net_pkt_rx_alloc_with_buffer(data->iface, len, AF_INET6, 0, K_FOREVER);

        if (net_pkt_write(pkt, data->buffer, len)) {
            goto drop;
        }

        if (net_recv_data(data->iface, pkt) < 0) {
            goto drop;
        }

drop:
        if (pkt) {
            net_pkt_unref(pkt);
        }
    }
}

static void interrupt_handler(const struct device *mux_dev, void *user_data)
{
	ARG_UNUSED(user_data);
    printk("Uart mux IRQ handler\n");

    struct uartmux_netif_data *data = user_data;

	while (uart_irq_update(mux_dev) && uart_irq_is_pending(mux_dev)) {
        int len;

		if (!uart_irq_rx_ready(mux_dev)) {
			continue;
		}

        // TODO: A mutex around buffer, multiple buffers, flow control, ACKs?
		while ((len = uart_fifo_read(mux_dev, data->buffer, BUFFER_SIZE))) {
            if (len > 0) {
                data->buffer_len = len;
                k_sem_give(&rx_sem);
#if 0
                // TODO: Push to network stack
                printk("Received buffer:");
                for (int i = 0; i < len; ++i) {
                    printk(" %02x", buffer[i]);
                }
                printk("\n");
#endif
            }
		}
	}
}

static void mux_attach_cb(const struct device *mux_dev, int dlci_address, bool connected, void *user_data)
{
    // Intentionally empty
}

static int uartmux_init(const struct device *dev)
{
    int r;
    struct uartmux_netif_data *data = DATA(dev);
    const struct uartmux_netif_cfg *cfg = CFG(dev);
    const struct device *uart_dev = device_get_binding(cfg->uart_name);

	if (!uart_dev) {
		return -ENODEV;
	}

    data->mux_dev = uart_mux_alloc();


    r = uart_mux_attach(data->mux_dev, uart_dev, INSTANCE + 1, mux_attach_cb, NULL);
    if (r) {
		return -ENODEV;
    }

    // TODO: Check error codes
    uart_irq_callback_user_data_set(data->mux_dev, interrupt_handler, data);

	/* Disable tx interrupts */
	uart_irq_tx_disable(data->mux_dev);
	/* Enable rx interrupts */
	uart_irq_rx_enable(data->mux_dev);

    return 0;
}

static void iface_init(struct net_if *iface)
{
    const struct device *dev = net_if_get_device(iface);
    struct uartmux_netif_data *data = DATA(dev);

    data->iface = iface;
}

struct dummy_api api = {
    .iface_api.init = iface_init,

    .send = send,
};

#define L2 DUMMY_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(DUMMY_L2)
#define MTU 1280

NET_DEVICE_INIT_INSTANCE(uartmux_netif, "UART mux net iface", INSTANCE,
        uartmux_init, device_pm_control_nop, &data, &cfg,
        INIT_PRIO, &api, L2, L2_CTX_TYPE, MTU);
