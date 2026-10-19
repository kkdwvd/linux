// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Experimental auxiliary Ethernet transport for bounded BPF driver algorithms.
 * The firmware objects, DMA mappings and hardware rings below are private to
 * this driver. BPF supplies packet capabilities and a checked SEND template;
 * it never supplies an address, lkey, queue number, or MMIO value.
 */
#include <linux/auxiliary_bus.h>
#include <linux/bpf_net_driver.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/module.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/eswitch.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/port.h>
#include <linux/mlx5/transobj.h>
#include <linux/mlx5/vport.h>

#include "eswitch.h"
#include "lib/clock.h"
#include "lib/eq.h"
#include "mlx5_core.h"
#include "wq.h"

#define MBN_LOG_WQ 7
#define MBN_LOG_CQ 8
#define MBN_WQ_SIZE BIT(MBN_LOG_WQ)
#define MBN_RX_DEPTH 32
#define MBN_TX_BUDGET 64
#define MBN_INLINE (ETH_HLEN + VLAN_HLEN)

struct mbnet;

struct mbnet_slot {
	struct bpf_net_driver_buffer *buffer;
	dma_addr_t dma;
	u32 dma_length;
};

struct mbnet_cq {
	struct mlx5_core_cq mcq;
	struct mlx5_cqwq wq;
	struct mlx5_wq_ctrl ctrl;
	struct mbnet *net;
	bool allocated;
	bool created;
};

struct mbnet_queue {
	struct mlx5_wq_cyc wq;
	struct mlx5_wq_ctrl ctrl;
	struct mbnet_slot slots[MBN_WQ_SIZE];
	u32 number;
	u16 producer;
	u16 consumer;
	bool allocated;
	bool created;
	bool ready;
	bool pending;
};

struct mbnet {
	struct mlx5_core_dev *mdev;
	struct bpf_net_driver *drv;
	struct mlx5_sq_bfreg bfreg;
	struct mbnet_cq cq[2];
	struct mbnet_queue queue[2];
	struct mlx5_flow_table *ft;
	struct mlx5_flow_handle *rule;
	u32 pdn;
	u32 tdn;
	u32 mkey;
	u32 tisn;
	u32 tirn;
	u32 rx_posted;
	int fatal;
	int saved_promisc[3];
	u16 saved_mtu;
	u16 saved_port_mtu;
	enum mlx5_port_status saved_port_status;
	u8 min_inline;
	bool have_bfreg;
	bool have_pd;
	bool have_td;
	bool have_mkey;
	bool have_tis;
	bool have_tir;
	bool restore_vport;
	bool restore_port;
	bool port_up;
	bool uncertain;
};

struct mbnet_tx_wqe {
	struct mlx5_wqe_ctrl_seg ctrl;
	struct mlx5_wqe_eth_seg eth;
	u8 inline_extra[16];
	struct mlx5_wqe_data_seg data;
};

/*
 * mlx5_cmd_exec() can synthesize successful DESTROY replies during an internal
 * error. That is useful for ordinary mlx5 teardown, but is not evidence that a
 * DMA buffer may be reused. Preserve the raw execution status for this ledger.
 */
static int mbnet_cmd(struct mbnet *net, void *in, int inlen, void *out, int outlen)
{
	return mlx5_cmd_do(net->mdev, in, inlen, out, outlen);
}

#define MBN_CMD(net, command, in, out) \
	mbnet_cmd(net, in, MLX5_ST_SZ_BYTES(command##_in), out, MLX5_ST_SZ_BYTES(command##_out))

#define MBN_DESTROY(name, command, opcode_value, field) \
static int mbnet_destroy_##name(struct mbnet *net, u32 id) \
{ \
	u32 in[MLX5_ST_SZ_DW(command##_in)] = {}; \
	u32 out[MLX5_ST_SZ_DW(command##_out)] = {}; \
	MLX5_SET(command##_in, in, opcode, opcode_value); \
	MLX5_SET(command##_in, in, field, id); \
	return MBN_CMD(net, command, in, out); \
}

MBN_DESTROY(pd, dealloc_pd, MLX5_CMD_OP_DEALLOC_PD, pd)
MBN_DESTROY(td, dealloc_transport_domain, MLX5_CMD_OP_DEALLOC_TRANSPORT_DOMAIN, transport_domain)
MBN_DESTROY(mkey, destroy_mkey, MLX5_CMD_OP_DESTROY_MKEY, mkey_index)
MBN_DESTROY(tis, destroy_tis, MLX5_CMD_OP_DESTROY_TIS, tisn)
MBN_DESTROY(tir, destroy_tir, MLX5_CMD_OP_DESTROY_TIR, tirn)
MBN_DESTROY(sq, destroy_sq, MLX5_CMD_OP_DESTROY_SQ, sqn)
MBN_DESTROY(rq, destroy_rq, MLX5_CMD_OP_DESTROY_RQ, rqn)

static int mbnet_alloc_pd(struct mbnet *net)
{
	u32 in[MLX5_ST_SZ_DW(alloc_pd_in)] = {};
	u32 out[MLX5_ST_SZ_DW(alloc_pd_out)] = {};
	int err;

	MLX5_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	err = MBN_CMD(net, alloc_pd, in, out);
	if (err)
		return err;
	net->pdn = MLX5_GET(alloc_pd_out, out, pd);
	net->have_pd = true;
	return 0;
}

static int mbnet_alloc_td(struct mbnet *net)
{
	u32 in[MLX5_ST_SZ_DW(alloc_transport_domain_in)] = {};
	u32 out[MLX5_ST_SZ_DW(alloc_transport_domain_out)] = {};
	int err;

	MLX5_SET(alloc_transport_domain_in, in, opcode, MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN);
	err = MBN_CMD(net, alloc_transport_domain, in, out);
	if (err)
		return err;
	net->tdn = MLX5_GET(alloc_transport_domain_out, out, transport_domain);
	net->have_td = true;
	return 0;
}

static int mbnet_create_mkey(struct mbnet *net)
{
	u32 in[MLX5_ST_SZ_DW(create_mkey_in)] = {};
	u32 out[MLX5_ST_SZ_DW(create_mkey_out)] = {};
	void *mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	int err;

	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_PA);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, pd, net->pdn);
	MLX5_SET(mkc, mkc, length64, 1);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	err = MBN_CMD(net, create_mkey, in, out);
	if (err)
		return err;
	net->mkey = mlx5_idx_to_mkey(MLX5_GET(create_mkey_out, out, mkey_index));
	net->have_mkey = true;
	return 0;
}

static int mbnet_create_tis(struct mbnet *net)
{
	u32 in[MLX5_ST_SZ_DW(create_tis_in)] = {};
	u32 out[MLX5_ST_SZ_DW(create_tis_out)] = {};
	void *tisc = MLX5_ADDR_OF(create_tis_in, in, ctx);
	int err;

	MLX5_SET(create_tis_in, in, opcode, MLX5_CMD_OP_CREATE_TIS);
	MLX5_SET(tisc, tisc, transport_domain, net->tdn);
	err = MBN_CMD(net, create_tis, in, out);
	if (err)
		return err;
	net->tisn = MLX5_GET(create_tis_out, out, tisn);
	net->have_tis = true;
	return 0;
}

static int mbnet_create_tir(struct mbnet *net)
{
	u32 in[MLX5_ST_SZ_DW(create_tir_in)] = {};
	u32 out[MLX5_ST_SZ_DW(create_tir_out)] = {};
	void *tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	int err;

	MLX5_SET(create_tir_in, in, opcode, MLX5_CMD_OP_CREATE_TIR);
	MLX5_SET(tirc, tirc, transport_domain, net->tdn);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_RX_HASH_FN_NONE);
	MLX5_SET(tirc, tirc, inline_rqn, net->queue[BPF_NET_DRIVER_RX].number);
	err = MBN_CMD(net, create_tir, in, out);
	if (err)
		return err;
	net->tirn = MLX5_GET(create_tir_out, out, tirn);
	net->have_tir = true;
	return 0;
}

static void mbnet_completion(struct mlx5_core_cq *mcq, struct mlx5_eqe *eqe)
{
	struct mbnet_cq *cq = container_of(mcq, struct mbnet_cq, mcq);

	bpf_net_driver_schedule(cq->net->drv);
}

static void mbnet_cq_error(struct mlx5_core_cq *mcq, enum mlx5_event event)
{
	struct mbnet_cq *cq = container_of(mcq, struct mbnet_cq, mcq);

	WRITE_ONCE(cq->net->fatal, -EIO);
	bpf_net_driver_error(cq->net->drv, -EIO);
}

static int mbnet_create_cq(struct mbnet *net, unsigned int index)
{
	struct mlx5_wq_param param = {
		.buf_numa_node = dev_to_node(mlx5_core_dma_dev(net->mdev)),
		.db_numa_node = dev_to_node(mlx5_core_dma_dev(net->mdev)),
	};
	u32 out[MLX5_ST_SZ_DW(create_cq_out)] = {};
	u32 context[MLX5_ST_SZ_DW(cqc)] = {};
	struct mbnet_cq *cq = &net->cq[index];
	void *in, *cqc;
	int eqn, inlen, err, i;

	err = mlx5_comp_eqn_get(net->mdev, 0, &eqn);
	if (err)
		return err;
	MLX5_SET(cqc, context, cqe_sz, CQE_STRIDE_64);
	MLX5_SET(cqc, context, log_cq_size, MBN_LOG_CQ);
	err = mlx5_cqwq_create(net->mdev, &param, context, &cq->wq, &cq->ctrl);
	if (err)
		return err;
	cq->allocated = true;
	cq->net = net;
	cq->mcq.cqe_sz = 64;
	cq->mcq.set_ci_db = cq->ctrl.db.db;
	cq->mcq.arm_db = cq->ctrl.db.db + 1;
	cq->mcq.vector = 0;
	cq->mcq.comp = mbnet_completion;
	cq->mcq.event = mbnet_cq_error;
	for (i = 0; i < BIT(MBN_LOG_CQ); i++)
		mlx5_cqwq_get_wqe(&cq->wq, i)->op_own = 0xf1;

	inlen = MLX5_ST_SZ_BYTES(create_cq_in) + sizeof(u64) * cq->ctrl.buf.npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);
	memcpy(cqc, context, sizeof(context));
	MLX5_SET(cqc, cqc, c_eqn_or_apu_element, eqn);
	MLX5_SET(cqc, cqc, uar_page, net->bfreg.up->index);
	MLX5_SET(cqc, cqc, log_page_size, cq->ctrl.buf.page_shift - MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(cqc, cqc, dbr_addr, cq->ctrl.db.dma);
	mlx5_fill_page_frag_array(&cq->ctrl.buf, MLX5_ADDR_OF(create_cq_in, in, pas));
	/* This variant preserves raw errors and registers the CQ in the EQ trees. */
	err = mlx5_create_cq(net->mdev, &cq->mcq, in, inlen, out, sizeof(out));
	kvfree(in);
	if (err) {
		net->uncertain = true;
		return err;
	}
	cq->created = true;
	return 0;
}

static int mbnet_destroy_cq(struct mbnet *net, struct mbnet_cq *cq)
{
	u32 in[MLX5_ST_SZ_DW(destroy_cq_in)] = {};
	u32 out[MLX5_ST_SZ_DW(destroy_cq_out)] = {};
	int err;

	if (!cq->created)
		return 0;
	mlx5_debug_cq_remove(net->mdev, &cq->mcq);
	mlx5_eq_del_cq(mlx5_get_async_eq(net->mdev), &cq->mcq);
	mlx5_eq_del_cq(&cq->mcq.eq->core, &cq->mcq);
	MLX5_SET(destroy_cq_in, in, opcode, MLX5_CMD_OP_DESTROY_CQ);
	MLX5_SET(destroy_cq_in, in, cqn, cq->mcq.cqn);
	err = MBN_CMD(net, destroy_cq, in, out);
	/* Drain callbacks even when DMA quiescence could not be established. */
	synchronize_irq(cq->mcq.irqn);
	mlx5_eq_synchronize_async_irq(net->mdev);
	mlx5_cq_put(&cq->mcq);
	wait_for_completion(&cq->mcq.free);
	cq->created = false;
	return err;
}

static int mbnet_modify_queue(struct mbnet *net, unsigned int index, bool ready)
{
	struct mbnet_queue *q = &net->queue[index];
	u32 in[MLX5_ST_SZ_DW(modify_sq_in)] = {};
	u32 out[MLX5_ST_SZ_DW(modify_sq_out)] = {};
	void *sqc = MLX5_ADDR_OF(modify_sq_in, in, ctx);

	if (index == BPF_NET_DRIVER_RX) {
		u32 in[MLX5_ST_SZ_DW(modify_rq_in)] = {};
		u32 out[MLX5_ST_SZ_DW(modify_rq_out)] = {};
		void *rqc = MLX5_ADDR_OF(modify_rq_in, in, ctx);

		MLX5_SET(modify_rq_in, in, opcode, MLX5_CMD_OP_MODIFY_RQ);
		MLX5_SET(modify_rq_in, in, rqn, q->number);
		MLX5_SET(modify_rq_in, in, rq_state,
			 ready ? MLX5_RQC_STATE_RST : MLX5_RQC_STATE_RDY);
		MLX5_SET(rqc, rqc, state, ready ? MLX5_RQC_STATE_RDY : MLX5_RQC_STATE_ERR);
		return MBN_CMD(net, modify_rq, in, out);
	}
	MLX5_SET(modify_sq_in, in, opcode, MLX5_CMD_OP_MODIFY_SQ);
	MLX5_SET(modify_sq_in, in, sqn, q->number);
	MLX5_SET(modify_sq_in, in, sq_state,
		 ready ? MLX5_SQC_STATE_RST : MLX5_SQC_STATE_RDY);
	MLX5_SET(sqc, sqc, state, ready ? MLX5_SQC_STATE_RDY : MLX5_SQC_STATE_ERR);
	return MBN_CMD(net, modify_sq, in, out);
}

static int mbnet_create_queue(struct mbnet *net, unsigned int index)
{
	struct mbnet_queue *q = &net->queue[index];
	struct mlx5_wq_param param = {
		.buf_numa_node = dev_to_node(mlx5_core_dma_dev(net->mdev)),
		.db_numa_node = dev_to_node(mlx5_core_dma_dev(net->mdev)),
	};
	u32 context[MLX5_ST_SZ_DW(wq)] = {};
	u32 out[MLX5_ST_SZ_DW(create_sq_out)] = {};
	bool rx = index == BPF_NET_DRIVER_RX;
	void *in, *qc, *wq;
	int err, inlen;

	MLX5_SET(wq, context, wq_type, MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq, context, log_wq_sz, MBN_LOG_WQ);
	MLX5_SET(wq, context, log_wq_stride, rx ? 4 : 6);
	MLX5_SET(wq, context, pd, net->pdn);
	if (rx)
		MLX5_SET(wq, context, end_padding_mode, MLX5_WQ_END_PAD_MODE_ALIGN);
	err = mlx5_wq_cyc_create(net->mdev, &param, context, &q->wq, &q->ctrl);
	if (err)
		return err;
	q->allocated = true;
	if (!rx)
		q->wq.db = &q->ctrl.db.db[MLX5_SND_DBR];
	inlen = (rx ? MLX5_ST_SZ_BYTES(create_rq_in) : MLX5_ST_SZ_BYTES(create_sq_in)) +
		sizeof(u64) * q->ctrl.buf.npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	if (rx) {
		MLX5_SET(create_rq_in, in, opcode, MLX5_CMD_OP_CREATE_RQ);
		qc = MLX5_ADDR_OF(create_rq_in, in, ctx);
		MLX5_SET(rqc, qc, cqn, net->cq[index].mcq.cqn);
		MLX5_SET(rqc, qc, state, MLX5_RQC_STATE_RST);
		MLX5_SET(rqc, qc, ts_format, mlx5_is_real_time_rq(net->mdev) ?
			 MLX5_TIMESTAMP_FORMAT_REAL_TIME : MLX5_TIMESTAMP_FORMAT_FREE_RUNNING);
		MLX5_SET(rqc, qc, vsd, 1);
		wq = MLX5_ADDR_OF(rqc, qc, wq);
	} else {
		MLX5_SET(create_sq_in, in, opcode, MLX5_CMD_OP_CREATE_SQ);
		qc = MLX5_ADDR_OF(create_sq_in, in, ctx);
		MLX5_SET(sqc, qc, cqn, net->cq[index].mcq.cqn);
		MLX5_SET(sqc, qc, state, MLX5_SQC_STATE_RST);
		MLX5_SET(sqc, qc, ts_format, mlx5_is_real_time_sq(net->mdev) ?
			 MLX5_TIMESTAMP_FORMAT_REAL_TIME : MLX5_TIMESTAMP_FORMAT_FREE_RUNNING);
		MLX5_SET(sqc, qc, flush_in_error_en, 1);
		MLX5_SET(sqc, qc, tis_lst_sz, 1);
		MLX5_SET(sqc, qc, tis_num_0, net->tisn);
		if (MLX5_CAP_ETH(net->mdev, wqe_inline_mode) == MLX5_CAP_INLINE_MODE_VPORT_CONTEXT)
			MLX5_SET(sqc, qc, min_wqe_inline_mode, net->min_inline);
		wq = MLX5_ADDR_OF(sqc, qc, wq);
	}
	memcpy(wq, context, sizeof(context));
	MLX5_SET(wq, wq, uar_page, net->bfreg.index);
	MLX5_SET(wq, wq, log_wq_pg_sz, q->ctrl.buf.page_shift - MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(wq, wq, dbr_addr, q->ctrl.db.dma);
	mlx5_fill_page_frag_array(&q->ctrl.buf, MLX5_ADDR_OF(wq, wq, pas));
	BUILD_BUG_ON(MLX5_ST_SZ_BYTES(create_rq_out) != MLX5_ST_SZ_BYTES(create_sq_out));
	err = mbnet_cmd(net, in, inlen, out, sizeof(out));
	kvfree(in);
	if (err) {
		net->uncertain = true;
		return err;
	}
	q->number = rx ? MLX5_GET(create_rq_out, out, rqn) : MLX5_GET(create_sq_out, out, sqn);
	q->created = true;
	err = mbnet_modify_queue(net, index, true);
	if (!err)
		q->ready = true;
	return err;
}

static int mbnet_steering(struct mbnet *net)
{
	struct mlx5_flow_table_attr attr = { .max_fte = 2, .autogroup.max_num_groups = 1 };
	struct mlx5_flow_destination dest = { .type = MLX5_FLOW_DESTINATION_TYPE_TIR };
	struct mlx5_flow_namespace *ns;
	MLX5_DECLARE_FLOW_ACT(act);

	ns = mlx5_get_flow_namespace(net->mdev, MLX5_FLOW_NAMESPACE_KERNEL);
	if (!ns)
		return -EOPNOTSUPP;
	net->ft = mlx5_create_auto_grouped_flow_table(ns, &attr);
	if (IS_ERR(net->ft)) {
		int err = PTR_ERR(net->ft);

		net->ft = NULL;
		return err;
	}
	dest.tir_num = net->tirn;
	net->rule = mlx5_add_flow_rules(net->ft, NULL, &act, &dest, 1);
	if (IS_ERR(net->rule)) {
		int err = PTR_ERR(net->rule);

		net->rule = NULL;
		return err;
	}
	return 0;
}

static int mbnet_save_port(struct mbnet *net)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)] = {};
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)] = {};
	int err;

	MLX5_SET(pmtu_reg, in, local_port, 1);
	err = mlx5_core_access_reg(net->mdev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_PMTU, 0, 0);
	if (err)
		return err;
	net->saved_port_mtu = MLX5_GET(pmtu_reg, out, admin_mtu);
	return mlx5_query_port_admin_status(net->mdev, &net->saved_port_status);
}

static int mbnet_start(struct bpf_net_driver *drv)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	struct mlx5_core_dev *mdev = net->mdev;
	struct net_device *dev = bpf_net_driver_netdev(drv);
	int err, i;

	if (net->uncertain || mlx5_cmd_is_down(mdev))
		return -EIO;
	WRITE_ONCE(net->fatal, 0);
	err = mlx5_alloc_bfreg(mdev, &net->bfreg, false, false);
	if (err)
		return err;
	net->have_bfreg = true;
	err = mbnet_alloc_pd(net);
	if (err)
		goto uncertain;
	err = mbnet_alloc_td(net);
	if (err)
		goto uncertain;
	err = mbnet_create_mkey(net);
	if (err)
		goto uncertain;
	err = mbnet_create_tis(net);
	if (err)
		goto uncertain;
	for (i = 0; i < ARRAY_SIZE(net->cq); i++) {
		err = mbnet_create_cq(net, i);
		if (err)
			return err;
		err = mbnet_create_queue(net, i);
		if (err)
			return err;
	}
	err = mbnet_create_tir(net);
	if (err)
		goto uncertain;
	err = mbnet_steering(net);
	if (err)
		goto uncertain;
	err = mlx5_query_nic_vport_promisc(mdev, 0, &net->saved_promisc[0],
					   &net->saved_promisc[1], &net->saved_promisc[2]);
	if (err)
		return err;
	err = mlx5_query_nic_vport_mtu(mdev, &net->saved_mtu);
	if (err)
		return err;
	err = mbnet_save_port(net);
	if (err)
		return err;
	net->restore_port = true;
	err = mlx5_set_port_mtu(mdev, dev->mtu + ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN, 1);
	if (err)
		return err;
	net->restore_vport = true;
	err = mlx5_modify_nic_vport_mtu(mdev, dev->mtu + ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN);
	if (err)
		return err;
	err = mlx5_modify_nic_vport_promisc(mdev, 1, 1, 1);
	if (err)
		return err;
	err = mlx5_set_port_admin_status(mdev, MLX5_PORT_UP);
	if (err)
		return err;
	net->port_up = true;
	if (MLX5_CAP_GEN(mdev, uplink_follow))
		return mlx5_eswitch_set_vport_state(mdev->priv.eswitch, MLX5_VPORT_UPLINK,
						    MLX5_VPORT_ADMIN_STATE_AUTO);
	return 0;
uncertain:
	/* A failed CREATE may have executed without delivering its resource ID. */
	net->uncertain = true;
	return err;
}

static int mbnet_stop(struct bpf_net_driver *drv)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	struct device *dma_dev = mlx5_core_dma_dev(net->mdev);
	int err = 0, restore_err, ret, i, j;

	if (net->port_up) {
		ret = mlx5_set_port_admin_status(net->mdev, MLX5_PORT_DOWN);
		if (ret)
			err = ret;
		else
			net->port_up = false;
	}
	if (net->restore_vport) {
		restore_err = mlx5_modify_nic_vport_promisc(net->mdev,
							    net->saved_promisc[0],
							    net->saved_promisc[1],
							    net->saved_promisc[2]);
		ret = mlx5_modify_nic_vport_mtu(net->mdev, net->saved_mtu);
		if (restore_err || ret)
			err = err ?: restore_err ?: ret;
		else
			net->restore_vport = false;
	}
	if (net->restore_port) {
		restore_err = mlx5_set_port_mtu(net->mdev, net->saved_port_mtu, 1);
		ret = mlx5_set_port_admin_status(net->mdev, net->saved_port_status);
		if (restore_err || ret)
			err = err ?: restore_err ?: ret;
		else
			net->restore_port = false;
	}
	/* Configuration errors must not bypass queue destruction or IRQ draining. */
	if (net->rule) {
		mlx5_del_flow_rules(net->rule);
		net->rule = NULL;
	}
	if (net->ft) {
		ret = mlx5_destroy_flow_table(net->ft);
		if (ret)
			err = ret;
		else
			net->ft = NULL;
	}
	if (net->have_tir) {
		ret = mbnet_destroy_tir(net, net->tirn);
		if (ret)
			err = ret;
		else
			net->have_tir = false;
	}
	for (i = 0; i < ARRAY_SIZE(net->queue); i++) {
		struct mbnet_queue *q = &net->queue[i];

		if (q->created) {
			if (q->ready)
				mbnet_modify_queue(net, i, false);
			ret = i == BPF_NET_DRIVER_RX ? mbnet_destroy_rq(net, q->number) :
							     mbnet_destroy_sq(net, q->number);
			if (ret)
				err = ret;
			else
				q->created = false;
		}
		ret = mbnet_destroy_cq(net, &net->cq[i]);
		if (ret)
			err = ret;
	}
	if (err || net->uncertain) {
		net->uncertain = true;
		return err ?: -EIO;
	}

	/* Both queues and CQs have acknowledged destruction before any DMA unmap. */
	for (i = 0; i < ARRAY_SIZE(net->queue); i++) {
		struct mbnet_queue *q = &net->queue[i];
		enum dma_data_direction direction = i == BPF_NET_DRIVER_RX ?
						    DMA_FROM_DEVICE : DMA_TO_DEVICE;

		for (j = 0; j < MBN_WQ_SIZE; j++) {
			struct mbnet_slot *slot = &q->slots[j];

			if (slot->buffer && slot->dma_length)
				dma_unmap_single(dma_dev, slot->dma, slot->dma_length, direction);
		}
		if (q->allocated)
			mlx5_wq_destroy(&q->ctrl);
		if (net->cq[i].allocated)
			mlx5_wq_destroy(&net->cq[i].ctrl);
		memset(q, 0, sizeof(*q));
		memset(&net->cq[i], 0, sizeof(net->cq[i]));
	}
	if (net->have_tis) {
		err = mbnet_destroy_tis(net, net->tisn);
		if (err)
			goto quarantine;
	}
	net->have_tis = false;
	if (net->have_mkey) {
		err = mbnet_destroy_mkey(net, mlx5_mkey_to_idx(net->mkey));
		if (err)
			goto quarantine;
	}
	net->have_mkey = false;
	if (net->have_td) {
		err = mbnet_destroy_td(net, net->tdn);
		if (err)
			goto quarantine;
	}
	net->have_td = false;
	if (net->have_pd) {
		err = mbnet_destroy_pd(net, net->pdn);
		if (err)
			goto quarantine;
	}
	net->have_pd = false;
	if (net->have_bfreg)
		mlx5_free_bfreg(net->mdev, &net->bfreg);
	net->have_bfreg = false;
	return 0;
quarantine:
	net->uncertain = true;
	return err;
}

static int mbnet_submit(struct bpf_net_driver *drv, unsigned int index,
			struct bpf_net_driver_buffer *buffer)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	struct device *dma_dev = mlx5_core_dma_dev(net->mdev);
	struct mbnet_queue *q = &net->queue[index];
	struct mbnet_slot *slot;
	void *wqe;
	u16 head;

	if (READ_ONCE(net->fatal) || !q->created || !q->ready)
		return -EIO;
	if ((u16)(q->producer - q->consumer) == MBN_WQ_SIZE)
		return -ENOSPC;
	if (buffer->offset)
		return -EINVAL;
	head = q->producer & (MBN_WQ_SIZE - 1);
	slot = &q->slots[head];
	if (slot->buffer)
		return -EIO;
	wqe = mlx5_wq_cyc_get_wqe(&q->wq, head);
	if (index == BPF_NET_DRIVER_RX) {
		struct mlx5_wqe_data_seg *data = wqe;

		if (buffer->submitted != BPF_NET_DRIVER_RX_SIZE)
			return -EINVAL;
		slot->dma_length = buffer->submitted;
		slot->dma = dma_map_single(dma_dev, buffer->skb->data, slot->dma_length,
					   DMA_FROM_DEVICE);
		if (dma_mapping_error(dma_dev, slot->dma))
			return -ENOMEM;
		data->byte_count = cpu_to_be32(slot->dma_length);
		data->lkey = cpu_to_be32(net->mkey);
		data->addr = cpu_to_be64(slot->dma);
	} else {
		const struct mlx5_wqe_ctrl_seg expected = {
			.opmod_idx_opcode = cpu_to_be32(MLX5_OPCODE_SEND),
			.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE,
		};
		struct mbnet_tx_wqe *tx = wqe;
		u32 inline_len = min_t(u32, buffer->submitted, MBN_INLINE);

		BUILD_BUG_ON(sizeof(*tx) != MLX5_SEND_WQE_BB);
		if (buffer->submitted < ETH_HLEN || buffer->submitted > ETH_FRAME_LEN + VLAN_HLEN ||
		    buffer->submitted != buffer->skb->len ||
		    memcmp(buffer->prefix, &expected, sizeof(expected)))
			return -EINVAL;
		memset(tx, 0, sizeof(*tx));
		memcpy(&tx->ctrl, buffer->prefix, sizeof(tx->ctrl));
		tx->ctrl.opmod_idx_opcode |= cpu_to_be32((u32)q->producer << 8);
		tx->ctrl.qpn_ds = cpu_to_be32(net->queue[BPF_NET_DRIVER_TX].number << 8 | 4);
		tx->eth.inline_hdr.sz = cpu_to_be16(inline_len);
		memcpy(tx->eth.inline_hdr.start, buffer->skb->data, 2);
		memcpy(tx->inline_extra, buffer->skb->data + 2, inline_len - 2);
		slot->dma_length = buffer->submitted - inline_len;
		if (slot->dma_length) {
			slot->dma = dma_map_single(dma_dev, buffer->skb->data + inline_len,
						   slot->dma_length, DMA_TO_DEVICE);
			if (dma_mapping_error(dma_dev, slot->dma))
				return -ENOMEM;
			tx->data.byte_count = cpu_to_be32(slot->dma_length);
			tx->data.lkey = cpu_to_be32(net->mkey);
			tx->data.addr = cpu_to_be64(slot->dma);
		} else {
			tx->ctrl.qpn_ds = cpu_to_be32(q->number << 8 | 3);
		}
	}
	slot->buffer = buffer;
	q->producer++;
	q->pending = true;
	return 0;
}

static struct bpf_net_driver_buffer *
mbnet_complete(struct bpf_net_driver *drv, unsigned int index, u32 *length)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	struct mbnet_queue *q = &net->queue[index];
	struct mlx5_cqwq *cq = &net->cq[index].wq;
	struct bpf_net_driver_buffer *buffer;
	struct mbnet_slot *slot;
	struct mlx5_cqe64 *cqe;
	u8 opcode;

	if (READ_ONCE(net->fatal))
		return ERR_PTR(-EIO);
	cqe = mlx5_cqwq_get_cqe(cq);
	if (!cqe)
		return NULL;
	opcode = index == BPF_NET_DRIVER_RX ? MLX5_CQE_RESP_SEND : MLX5_CQE_REQ;
	if (get_cqe_opcode(cqe) != opcode || mlx5_get_cqe_format(cqe) ||
	    be16_to_cpu(cqe->wqe_counter) != q->consumer || q->consumer == q->producer)
		return ERR_PTR(-EPROTO);
	slot = &q->slots[q->consumer & (MBN_WQ_SIZE - 1)];
	buffer = slot->buffer;
	if (!buffer)
		return ERR_PTR(-EPROTO);
	if (index == BPF_NET_DRIVER_RX && be32_to_cpu(cqe->byte_cnt) > slot->dma_length)
		return ERR_PTR(-EPROTO);
	*length = index == BPF_NET_DRIVER_RX ? be32_to_cpu(cqe->byte_cnt) : buffer->submitted;
	if (slot->dma_length)
		dma_unmap_single(mlx5_core_dma_dev(net->mdev), slot->dma, slot->dma_length,
				 index == BPF_NET_DRIVER_RX ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	memset(slot, 0, sizeof(*slot));
	q->consumer++;
	mlx5_cqwq_pop(cq);
	mlx5_cqwq_update_db_record(cq);
	return buffer;
}

static void mbnet_kick(struct bpf_net_driver *drv, unsigned int index)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	struct mbnet_queue *q = &net->queue[index];

	if (!q->pending)
		return;
	/* Publish all descriptor stores before making the producer visible. */
	dma_wmb();
	*q->wq.db = cpu_to_be32(q->producer);
	if (index == BPF_NET_DRIVER_TX) {
		struct mbnet_tx_wqe *last;

		last = mlx5_wq_cyc_get_wqe(&q->wq, (q->producer - 1) & (MBN_WQ_SIZE - 1));
		/* Order the host-memory producer update before the PCI doorbell. */
		wmb();
		mlx5_write64((__be32 *)&last->ctrl, net->bfreg.map);
	}
	q->pending = false;
}

static void mbnet_mask(struct bpf_net_driver *drv)
{
	/* CQ notifications are one-shot. The EQ callback only schedules NAPI. */
}

static bool mbnet_rearm(struct bpf_net_driver *drv)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	bool pending = false;
	int i;

	for (i = 0; i < ARRAY_SIZE(net->cq); i++)
		mlx5_cq_arm(&net->cq[i].mcq, MLX5_CQ_DB_REQ_NOT, net->bfreg.up->map,
			    net->cq[i].wq.cc);
	for (i = 0; i < ARRAY_SIZE(net->cq); i++)
		pending |= !!mlx5_cqwq_get_cqe(&net->cq[i].wq);
	return pending || READ_ONCE(net->fatal);
}

static void mbnet_refill(struct bpf_net_driver *drv)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	int i;
	u64 id;

	for (i = 0; i < MBN_RX_DEPTH && net->rx_posted < MBN_RX_DEPTH; i++) {
		id = bpf_net_buffer_alloc(drv);
		if (!id)
			break;
		if (bpf_net_queue_submit(drv, id, BPF_NET_DRIVER_RX, 0, BPF_NET_DRIVER_RX_SIZE)) {
			bpf_net_buffer_release(drv, id);
			break;
		}
		net->rx_posted++;
	}
	bpf_net_queue_kick(drv, BPF_NET_DRIVER_RX);
}

static int mbnet_native_open(struct bpf_net_driver *drv)
{
	struct mbnet *net = bpf_net_driver_private(drv);

	net->rx_posted = 0;
	mbnet_refill(drv);
	return 0;
}

static int mbnet_native_poll(struct bpf_net_driver *drv, int budget)
{
	struct mbnet *net = bpf_net_driver_private(drv);
	int tx, rx;
	u32 length;
	u64 id;

	for (tx = 0; tx < MBN_TX_BUDGET; tx++) {
		id = bpf_net_queue_complete(drv, BPF_NET_DRIVER_TX);
		if (!id)
			break;
		bpf_net_buffer_release(drv, id);
	}
	for (rx = 0; rx < budget; rx++) {
		id = bpf_net_queue_complete(drv, BPF_NET_DRIVER_RX);
		if (!id)
			break;
		if (net->rx_posted)
			net->rx_posted--;
		length = bpf_net_buffer_length(drv, id);
		if (length < ETH_HLEN)
			bpf_net_buffer_release(drv, id);
		else
			bpf_net_receive(drv, id, 0, length);
	}
	mbnet_refill(drv);
	return tx == MBN_TX_BUDGET ? budget : rx;
}

static int mbnet_native_xmit(struct bpf_net_driver *drv, u64 id)
{
	int err;

	/* Store the 16-byte control segment in the same byte order as BPF. */
	bpf_net_buffer_store(drv, id, 0, 8, 0x0a000000);
	bpf_net_buffer_store(drv, id, 8, 8, 0x08000000);
	err = bpf_net_queue_submit(drv, id, BPF_NET_DRIVER_TX, 0, bpf_net_buffer_length(drv, id));
	if (err)
		bpf_net_buffer_release(drv, id);
	else
		bpf_net_queue_kick(drv, BPF_NET_DRIVER_TX);
	return 0;
}

static void mbnet_native_close(struct bpf_net_driver *drv)
{
	struct mbnet *net = bpf_net_driver_private(drv);

	net->rx_posted = 0;
}

static const struct bpf_net_driver_ops mbnet_native_ops = {
	.open = mbnet_native_open,
	.poll = mbnet_native_poll,
	.xmit = mbnet_native_xmit,
	.close = mbnet_native_close,
};

static const struct bpf_net_driver_backend mbnet_backend = {
	.start = mbnet_start,
	.stop = mbnet_stop,
	.submit = mbnet_submit,
	.complete = mbnet_complete,
	.kick = mbnet_kick,
	.mask = mbnet_mask,
	.rearm = mbnet_rearm,
	.native_ops = &mbnet_native_ops,
};

static int mbnet_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct mlx5_core_dev *mdev = container_of(adev, struct mlx5_adev, adev)->mdev;
	struct net_device *dev;
	struct mbnet *net;
	u8 mac[ETH_ALEN];
	u8 min_inline = MLX5_INLINE_MODE_L2;
	int err;

	if (!mlx5_core_is_pf(mdev) || mlx5_core_is_ecpf(mdev) || pci_num_vf(mdev->pdev) ||
	    mlx5_lag_is_active(mdev) || mlx5_eswitch_mode(mdev) != MLX5_ESWITCH_LEGACY ||
	    MLX5_CAP_GEN(mdev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		return -EOPNOTSUPP;
	mlx5_query_min_inline(mdev, &min_inline);
	if (min_inline > MLX5_INLINE_MODE_L2)
		return -EOPNOTSUPP;
	err = mlx5_query_nic_vport_mac_address(mdev, 0, false, mac);
	if (err)
		return err;
	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;
	dev = alloc_etherdev(sizeof(*net));
	if (!dev)
		return -ENOMEM;
	net = netdev_priv(dev);
	net->mdev = mdev;
	net->min_inline = min_inline;
	strscpy(dev->name, "bpfm%d", IFNAMSIZ);
	eth_hw_addr_set(dev, mac);
	SET_NETDEV_DEV(dev, &adev->dev);
	net->drv = bpf_net_driver_create(dev, &mbnet_backend, net);
	if (IS_ERR(net->drv)) {
		err = PTR_ERR(net->drv);
		free_netdev(dev);
		return err;
	}
	auxiliary_set_drvdata(adev, net->drv);
	err = bpf_net_driver_register(net->drv);
	if (err) {
		bpf_net_driver_destroy(net->drv);
		auxiliary_set_drvdata(adev, NULL);
	}
	return err;
}

static void mbnet_remove(struct auxiliary_device *adev)
{
	struct bpf_net_driver *drv = auxiliary_get_drvdata(adev);

	bpf_net_driver_destroy(drv);
	auxiliary_set_drvdata(adev, NULL);
}

static const struct auxiliary_device_id mbnet_ids[] = {
	{ .name = MLX5_ADEV_NAME ".eth" },
	{},
};
MODULE_DEVICE_TABLE(auxiliary, mbnet_ids);

static struct auxiliary_driver mbnet_driver = {
	.name = "bpf_net",
	.probe = mbnet_probe,
	.remove = mbnet_remove,
	.id_table = mbnet_ids,
};

int mlx5_bpf_net_init(void)
{
	return auxiliary_driver_register(&mbnet_driver);
}

void mlx5_bpf_net_cleanup(void)
{
	auxiliary_driver_unregister(&mbnet_driver);
}
