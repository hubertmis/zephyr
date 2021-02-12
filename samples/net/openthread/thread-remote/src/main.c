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

#define APP_BANNER "***** OpenThread NCP on Zephyr %s *****"


int net_recv_data (struct net_if *iface, struct net_pkt *pkt)
{
    // TODO: Send pkt over UART
    return -1;
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

void mux_attach_cb(const struct device *mux, int dlci_address, bool connected, void *user_data)
{
    // Intentionally empty
}

void uart_mux_init(void)
{
    int r;
    const struct device *uart_dev = device_get_binding("uart1");

	if (!uart_dev) {
		return;
	}

    const struct device *mux_dev = uart_mux_alloc();


    r = uart_mux_attach(mux_dev, uart_dev, 0, mux_attach_cb, NULL);
    if (!r) {
        return;
    }
}

void main(void)
{
#if defined(CONFIG_OPENTHREAD_COPROCESSOR_SPINEL_ON_UART_ACM)
	const struct device *dev;
	uint32_t baudrate = 0U;
	int ret;

	dev = device_get_binding(
		CONFIG_OPENTHREAD_COPROCESSOR_SPINEL_ON_UART_DEV_NAME);
	if (!dev) {
		LOG_ERR("UART device not found");
		return;
	}

	ret = usb_enable(NULL);
	if (ret != 0) {
		LOG_ERR("Failed to enable USB");
		return;
	}

	LOG_INF("Wait for host to settle");
	k_sleep(K_SECONDS(1));

	ret = uart_line_ctrl_get(dev, UART_LINE_CTRL_BAUD_RATE, &baudrate);
	if (ret) {
		LOG_WRN("Failed to get baudrate, ret code %d", ret);
	} else {
		LOG_INF("Baudrate detected: %d", baudrate);
	}
#endif /* CONFIG_OPENTHREAD_COPROCESSOR_SPINEL_ON_UART_ACM */

	LOG_INF(APP_BANNER, CONFIG_NET_SAMPLE_APPLICATION_VERSION);
}
