/*
 ** Copyright (c) 2014, Linaro Limited
 ** All rights reserved.
 **
 ** SPDX-License-Identifier:      BSD-3-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "daq_api.h"
#include "sfbpf.h"

#include <odp.h>
#include <helper/odp_linux.h>
#include <helper/odp_packet_helper.h>
#include <helper/odp_eth.h>
#include <helper/odp_ip.h>

#define MAX_WORKERS            1
#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856
#define MAX_PKT_BURST          16
#define ODP_DEBUG		1

typedef struct _odp_context
{
	volatile int break_loop;
	DAQ_Stats_t stats;
	DAQ_State state;
	odp_queue_t inq_def;
	odp_pktio_t pktio;
	int snaplen;
	char *device;
	char errbuf[256];
} ODP_Context_t;

static int odp_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
	ODP_Context_t *odpc;
	int rval = DAQ_ERROR;
	int thr_id;
	odp_buffer_pool_t pool;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;
	odp_queue_param_t qparam;
	char inq_name[ODP_QUEUE_NAME_LEN];
	int ret;
	void *pool_base;

	rval = DAQ_ERROR;

	odpc = calloc(1, sizeof(ODP_Context_t));
	if (!odpc)
	{
		snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new ODP context!", __FUNCTION__);
		rval = DAQ_ERROR_NOMEM;
		goto err;
	}

	odpc->device = strdup(config->name);
	if (!odpc->device)
	{
		snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
		rval = DAQ_ERROR_NOMEM;
		goto err;
	}

	*ctxt_ptr = odpc;

	/* Init ODP before calling anything else */
	if (odp_init_global()) {
		ODP_ERR("Error: ODP global init failed.\n");
		goto err;
	}

	/* Init this thread */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/* Create packet pool */
	pool_base = odp_shm_reserve("shm_packet_pool",
				    SHM_PKT_POOL_SIZE, ODP_CACHE_LINE_SIZE);
	if (pool_base == NULL) {
		ODP_ERR("Error: packet pool mem alloc failed.\n");
		rval = DAQ_ERROR_NOMEM;
		goto err;
	}

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PKT_POOL_SIZE,
				      SHM_PKT_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);
	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: packet pool create failed.\n");
		rval = DAQ_ERROR;
		goto err;
	}
	odpc->snaplen = SHM_PKT_POOL_BUF_SIZE;
	odp_buffer_pool_print(pool);

	/* Open a packet IO instance for this thread */
	sock_params->type = ODP_PKTIO_TYPE_SOCKET_MMAP;
	sock_params->fanout = 0;

	odpc->pktio = odp_pktio_open(odpc->device, pool, &params);
	if (odpc->pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("  [%02i] Error: pktio create failed\n", 1 /*thr*/);
		rval = DAQ_ERROR_NODEV;
		goto err;
	}

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def", (int)odpc->pktio);
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	odpc->inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (odpc->inq_def == ODP_QUEUE_INVALID) {
		ODP_ERR("  [%02i] Error: pktio queue creation failed\n", 1 /*thr*/);
		goto err;
	}

	ret = odp_pktio_inq_setdef(odpc->pktio, odpc->inq_def);
	if (ret != 0) {
		ODP_ERR("  [%02i] Error: default input-Q setup\n", 1 /*thr*/);
		goto err;
	}

        odpc->state = DAQ_STATE_INITIALIZED;

	printf("%s() DAQ_SUCCESS.\n\n", __func__);
	return DAQ_SUCCESS;
err:

	return rval;
}

static int odp_daq_set_filter(void *handle, const char *filter)
{
	/* not implemented yet */
	return DAQ_SUCCESS;
}

static int odp_daq_start(void *handle)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;
	if (!odpc)
		return DAQ_ERROR_NOCTX;

	odpc->state = DAQ_STATE_STARTED;
	return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
	DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
	DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
	DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int odp_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
	ODP_Context_t *odpc;
	DAQ_PktHdr_t daqhdr;
	DAQ_Verdict verdict;
	const uint8_t *data;
	odp_packet_t pkt;
	int i;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int pkts;

	odpc = (ODP_Context_t *) handle;
	if (!odpc)
		return DAQ_ERROR;

	if (odpc->state != DAQ_STATE_STARTED)
		return DAQ_ERROR;

	while (1)
	{
		/* Has breakloop() been called? */
		if (odpc->break_loop)
		{
			odpc->break_loop = 0;
			return 0;
		}

		pkts = odp_pktio_recv(odpc->pktio, pkt_tbl, MAX_PKT_BURST);
		if (pkts <= 0) {
			return 0;
		}

		for (i = 0; i < pkts; ++i) {
			pkt = pkt_tbl[i];

			data = odp_packet_l2(pkt);
			if (!data) {
				//printf("no l2 offset, packet dropped\n");
				odpc->stats.packets_filtered++;
				odp_buffer_free(pkt);
				continue;
			}

			verdict = DAQ_VERDICT_PASS;

			gettimeofday(&daqhdr.ts, NULL);
			daqhdr.caplen = odp_buffer_size(pkt);

			daqhdr.pktlen = odp_packet_get_len(pkt);
			daqhdr.ingress_index = 0;
			daqhdr.egress_index =  DAQ_PKTHDR_UNKNOWN;
			daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
			daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
			daqhdr.flags = 0;
			daqhdr.opaque = 0;
			daqhdr.priv_ptr = NULL;
			daqhdr.address_space_id = 0;

			if (callback)
			{
				verdict = callback(user, &daqhdr, data);
				if (verdict >= MAX_DAQ_VERDICT)
					verdict = DAQ_VERDICT_PASS;
				odpc->stats.verdicts[verdict]++;
				verdict = verdict_translation_table[verdict];
			}

			odp_buffer_free(pkt);
		}

		if (pkts > 0) {
			odpc->stats.packets_received += pkts;
			break;
		}
	}
	return 0;
}

static int odp_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    return DAQ_SUCCESS;
}

static int odp_daq_breakloop(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    odpc->break_loop = 1;
    return DAQ_SUCCESS;
}

static int odp_daq_stop(void *handle)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	odpc->break_loop = 1;
	odp_timer_disarm_all();
	odpc->state = DAQ_STATE_STOPPED;

	return DAQ_SUCCESS;
}

static void odp_daq_shutdown(void *handle)
{
	odp_timer_disarm_all();
}

static DAQ_State odp_daq_check_status(void *handle)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	if (!odpc) {
		return DAQ_STATE_UNINITIALIZED;
	}

	return odpc->state;
}

static int odp_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	memcpy(stats, &odpc->stats, sizeof(DAQ_Stats_t));
	return DAQ_SUCCESS;
}

static void odp_daq_reset_stats(void *handle)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	memset(&odpc->stats, 0, sizeof(DAQ_Stats_t));
}

static int odp_daq_get_snaplen(void *handle)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	if (odpc)
		return odpc->snaplen;

	return 1500;
}

static uint32_t odp_daq_get_capabilities(void *handle)
{
	return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_DEVICE_INDEX;
}

static int odp_daq_get_datalink_type(void *handle)
{
	return DLT_EN10MB;
}

static const char *odp_daq_get_errbuf(void *handle)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	return odpc->errbuf;
}

static void odp_daq_set_errbuf(void *handle, const char *string)
{
	ODP_Context_t *odpc = (ODP_Context_t *) handle;

	if (!string)
		return;

	DPE(odpc->errbuf, "%s", string);
	return;
}

static int odp_daq_get_device_index(void *handle, const char *string)
{
	return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t afpacket_daq_module_data =
#endif
{
	.api_version = DAQ_API_VERSION,
	.module_version = 1,
	.name = "odp",
	.type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
	.initialize = odp_daq_initialize,
	.set_filter = odp_daq_set_filter,
	.start = odp_daq_start,
	.acquire = odp_daq_acquire,
	.inject = odp_daq_inject,
	.breakloop = odp_daq_breakloop,
	.stop = odp_daq_stop,
	.shutdown = odp_daq_shutdown,
	.check_status = odp_daq_check_status,
	.get_stats = odp_daq_get_stats,
	.reset_stats = odp_daq_reset_stats,
	.get_snaplen = odp_daq_get_snaplen,
	.get_capabilities = odp_daq_get_capabilities,
	.get_datalink_type = odp_daq_get_datalink_type,
	.get_errbuf = odp_daq_get_errbuf,
	.set_errbuf = odp_daq_set_errbuf,
	.get_device_index = odp_daq_get_device_index,
	.modify_flow = NULL,
	.hup_prep = NULL,
	.hup_apply = NULL,
	.hup_post = NULL,
};
