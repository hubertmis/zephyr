/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>

#include <zephyr/ipc/ipc_service.h>

#define STACKSIZE	(1024)
#define PRIORITY	K_PRIO_PREEMPT(2)

struct ept_data {
	const struct device *ipc_instance;
	int ept_id;
	struct ipc_ept_cfg ept_cfg;
	volatile uint8_t received_data;
	struct k_sem bound_sem;
	struct k_sem data_sem;
	const char label[];
};

static void ipc_ept_bound(void *priv);
static void ipc_ept_recv(const void *data, size_t len, void *priv);
static void ipc_ept_entry(void *arg0, void *dummy1, void *dummy2);

#define CREATE_IPC_THREAD_FOR_ENDPOINT(NODE_ID, EPT_NUM)			\
	K_THREAD_STACK_DEFINE(ipc ## NODE_ID ## EPT_NUM ## _stack, STACKSIZE);	\
	static struct ept_data ipc ## NODE_ID ## EPT_NUM ## _data = {		\
		.ipc_instance = DEVICE_DT_GET(NODE_ID),				\
		.ept_id = EPT_NUM,						\
		.ept_cfg = {							\
			.name = #EPT_NUM,					\
			.cb = {							\
				.bound    = ipc_ept_bound,			\
				.received = ipc_ept_recv,			\
			},							\
			.priv = &ipc ## NODE_ID ## EPT_NUM ## _data,		\
		},								\
		.label = DT_NODE_FULL_NAME(NODE_ID),				\
	};									\
	K_THREAD_DEFINE(ipc ## NODE_ID ## EPT_NUM ## _thread_id, STACKSIZE,	\
			ipc_ept_entry, &ipc ## NODE_ID ## EPT_NUM ## _data,	\
		       	NULL, NULL, PRIORITY, 0, 0);

// TODO: some kind of a loop instead?
#define CREATE_IPC_THREADS(NODE_ID)						\
	CREATE_IPC_THREAD_FOR_ENDPOINT(NODE_ID, 0)				\
	CREATE_IPC_THREAD_FOR_ENDPOINT(NODE_ID, 1)

DT_FOREACH_CHILD(DT_PATH(ipc), CREATE_IPC_THREADS)

#define CREATE_INSTANCE(NODE_ID)						\
		DEVICE_DT_GET(NODE_ID),

static const struct device *instances_array[] = {
	DT_FOREACH_CHILD(DT_PATH(ipc), CREATE_INSTANCE)
};


/* Determine if the caller should delay an endpoint registration.
 *
 * Even endpoints in odd instances in remote delay registration.
 * Odd endpoints in even instances in remote delay registration.
 * Other endpoints do not delay.
 */
static bool should_delay_registration(int instance_id, int ept_id)
{
	if ((!(instance_id % 2)) && (ept_id % 2)) {
		return true;
	}
	if ((instance_id % 2) && (!(ept_id % 2))) {
		return true;
	}

	return false;
}

static void ipc_ept_bound(void *priv)
{
	struct ept_data *ept_data = priv;

	k_sem_give(&ept_data->bound_sem);
}

static void ipc_ept_recv(const void *data, size_t len, void *priv)
{
	struct ept_data *ept_data = priv;

	ept_data->received_data = *((uint8_t *) data);
	k_sem_give(&ept_data->data_sem);
}

static void ipc_ept_entry(void *arg0, void *dummy1, void *dummy2)
{
	ARG_UNUSED(dummy1);
	ARG_UNUSED(dummy2);

	struct ept_data *ept_data = arg0;

	unsigned char message = 0;
	struct ipc_ept ipc_ept;
	int ret;

	int inst_id;
	for (inst_id = 0; inst_id < ARRAY_SIZE(instances_array); inst_id++) {
		if (instances_array[inst_id] == ept_data->ipc_instance) {
			break;
		}
	}

	if (inst_id >= ARRAY_SIZE(instances_array)) {
		printk("IPC-service REMOTE [INST %s - ENDP %s] demo "
				"cannot start. Missing instance id\n",
				ept_data->label, ept_data->ept_cfg.name);
		return;
	}

	printk("IPC-service REMOTE [INST %s - ENDP %s] demo started\n",
		       ept_data->label, ept_data->ept_cfg.name);

	k_sem_init(&ept_data->bound_sem, 0, 1);
	k_sem_init(&ept_data->data_sem, 0, 1);

	ret = ipc_service_open_instance(ept_data->ipc_instance);
	if (ret < 0 && ret != -EALREADY) {
		printk("ipc_service_open_instance() failure\n");
		return;
	}

	if (should_delay_registration(inst_id, ept_data->ept_id)) {
		/*
		 * Wait 1 sec to give the opportunity to the HOST core to register
		 * the endpoint first
		 */

		k_sleep(K_MSEC(1000));
	}
	
	// TODO: Skip registration if ept_data->ept_id > 0 && this instance does not support multiple endpoints

	ret = ipc_service_register_endpoint(ept_data->ipc_instance, &ipc_ept, &ept_data->ept_cfg);
	if (ret < 0) {
		printf("ipc_service_register_endpoint() failure\n");
		return;
	}

	k_sem_take(&ept_data->bound_sem, K_FOREVER);

	while (message < 99) {
		k_sem_take(&ept_data->data_sem, K_FOREVER);
		message = ept_data->received_data;
		size_t message_len = sizeof(message);

		printk("REMOTE [%s:%s]: %d\n", ept_data->label,
				ept_data->ept_cfg.name, message);

		message++;

		ret = ipc_service_send(&ipc_ept, &message, message_len);
		if (ret < 0) {
			printk("send_message(%d) failed with ret %d\n", message, ret);
			break;
		} else if (ret != message_len) {
			printk("sent %d bytes instead of requested %d\n", ret, message_len);
			break;
		}
	}

	printk("IPC-service REMOTE [INST %s - ENDP %s] demo ended.\n",
		       ept_data->label, ept_data->ept_cfg.name);
}
