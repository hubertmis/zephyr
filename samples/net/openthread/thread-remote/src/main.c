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


int net_recv_data (struct net_if *iface, struct net_pkt *pkt)
{
    enum net_verdict verd;

    if (!pkt || !iface) {
        return -EINVAL;
    }

    if (net_pkt_is_empty(pkt)) {
        return -ENODATA;
    }

    if (!net_if_flag_is_set(iface, NET_IF_UP)) {
        return -ENETDOWN;
    }

    net_pkt_set_overwrite(pkt, true);
    net_pkt_cursor_init(pkt);

    NET_DBG("prio %d iface %p pkt %p len %zu", net_pkt_priority(pkt),
        iface, pkt, net_pkt_get_len(pkt));

    if (IS_ENABLED(CONFIG_NET_ROUTING)) {
        net_pkt_set_orig_iface(pkt, iface);
    }

    net_pkt_set_iface(pkt, iface);

    verd = net_if_l2(iface)->recv(iface, pkt);

    if (verd == NET_CONTINUE) {
        struct net_buf *buf;

        buf = net_buf_frag_last(pkt->buffer);

        uart_fifo_fill(mux_dev, buf->data, buf->len);
    }
    return 0;
}


struct net_if_addr* net_if_ipv6_addr_add (struct net_if * iface, struct in6_addr * addr, enum net_addr_type addr_type, uint32_t vlifetime)
{
    // TODO: Send address over UART
    return NULL;
}

struct net_if_mcast_addr* net_if_ipv6_maddr_lookup (const struct in6_addr * addr, struct net_if ** iface)
{
    // TODO: Check address in remote stack
    return NULL;
}


struct net_if_mcast_addr* net_if_ipv6_maddr_add (struct net_if * iface, const struct in6_addr * addr)	
{
    // TODO: Add address over UART
    return NULL;
}


int net_if_config_ipv6_get (struct net_if * iface, struct net_if_ipv6 ** ipv6)
{
    // TODO: Not sure what this function is supposed to do. Verify
    return -1;
}

int net_bytes_from_str(uint8_t *buf, int buf_len, const char *src)
{
	unsigned int i;
	char *endptr;

	for (i = 0U; i < strlen(src); i++) {
		if (!(src[i] >= '0' && src[i] <= '9') &&
		    !(src[i] >= 'A' && src[i] <= 'F') &&
		    !(src[i] >= 'a' && src[i] <= 'f') &&
		    src[i] != ':') {
			return -EINVAL;
		}
	}

	(void)memset(buf, 0, buf_len);

	for (i = 0U; i < buf_len; i++) {
		buf[i] = strtol(src, &endptr, 16);
		src = ++endptr;
	}

	return 0;
}

////////// TEST UART_MUX ////////////////////

#include <drivers/console/uart_mux.h>

static void interrupt_handler(const struct device *dev, void *user_data)
{
    ARG_UNUSED(user_data);

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

// Copied from net_if.c
static inline void init_iface(struct net_if *iface)
{
    const struct net_if_api *api = net_if_get_device(iface)->api;

    if (!api || !api->init) {
        NET_ERR("Iface %p driver API init NULL", iface);
        return;
    }

    NET_DBG("On iface %p", iface);

#ifdef CONFIG_USERSPACE
    z_object_init(iface);
#endif

    api->init(iface);
}

// Copied from net_if.c
int net_if_up(struct net_if *iface)
{
    int status;

    NET_DBG("iface %p", iface);

    if (net_if_flag_is_set(iface, NET_IF_UP)) {
        return 0;
    }

    if ((IS_ENABLED(CONFIG_NET_OFFLOAD) &&
         net_if_is_ip_offloaded(iface)) ||
        (IS_ENABLED(CONFIG_NET_SOCKETS_OFFLOAD) &&
         net_if_is_socket_offloaded(iface))) {
        net_if_flag_set(iface, NET_IF_UP);
        goto exit;
    }

    /* If the L2 does not support enable just set the flag */
    if (!net_if_l2(iface) || !net_if_l2(iface)->enable) {
        goto done;
    }

    /* Notify L2 to enable the interface */
    status = net_if_l2(iface)->enable(iface, true);
    if (status < 0) {
        return status;
    }

done:
    /* In many places it's assumed that link address was set with
     * net_if_set_link_addr(). Better check that now.
     */
    NET_ASSERT(net_if_get_link_addr(iface)->addr != NULL);

    net_if_flag_set(iface, NET_IF_UP);

#if 0
    /* If the interface is only having point-to-point traffic then we do
     * not need to run DAD etc for it.
     */
    if (!(l2_flags_get(iface) & NET_L2_POINT_TO_POINT)) {
        iface_ipv6_start(iface);

        net_ipv4_autoconf_start(iface);
    }
#endif

exit:
    net_mgmt_event_notify(NET_EVENT_IF_UP, iface);

    return 0;
}

void main(void)
{
	LOG_INF(APP_BANNER, CONFIG_NET_SAMPLE_APPLICATION_VERSION);

    uart_mux_init();

    Z_STRUCT_SECTION_FOREACH(net_if, iface) {
        init_iface(iface);
        if (!net_if_flag_is_set(iface, NET_IF_NO_AUTO_START)) {
            net_if_up(iface);
        }
    }
}
