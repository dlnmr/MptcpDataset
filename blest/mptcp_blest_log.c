// SPDX-License-Identifier: GPL-2.0
/*	MPTCP Scheduler to reduce HoL-blocking and spurious retransmissions.
 *
 *	Algorithm Design:
 *	Simone Ferlin <ferlin@simula.no>
 *	Ozgu Alay <ozgu@simula.no>
 *	Olivier Mehani <olivier.mehani@nicta.com.au>
 *	Roksana Boreli <roksana.boreli@nicta.com.au>
 *
 *	Initial Implementation:
 *	Simone Ferlin <ferlin@simula.no>
 *
 *	Additional Authors:
 *	Daniel Weber <weberd@cs.uni-bonn.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char lambda __read_mostly = 12;
module_param(lambda, byte, 0644);
MODULE_PARM_DESC(lambda, "Divided by 10 for scaling factor of fast flow rate estimation");

static unsigned char max_lambda __read_mostly = 13;
module_param(max_lambda, byte, 0644);
MODULE_PARM_DESC(max_lambda, "Divided by 10 for maximum scaling factor of fast flow rate estimation");

static unsigned char min_lambda __read_mostly = 10;
module_param(min_lambda, byte, 0644);
MODULE_PARM_DESC(min_lambda, "Divided by 10 for minimum scaling factor of fast flow rate estimation");

static unsigned char dyn_lambda_good = 10; /* 1% */
module_param(dyn_lambda_good, byte, 0644);
MODULE_PARM_DESC(dyn_lambda_good, "Decrease of lambda in positive case.");

static unsigned char dyn_lambda_bad = 40; /* 4% */
module_param(dyn_lambda_bad, byte, 0644);
MODULE_PARM_DESC(dyn_lambda_bad, "Increase of lambda in negative case.");

struct blestsched_priv {
	u32 last_rbuf_opti;
	u32 min_srtt_us;
	u32 max_srtt_us;
};

struct blestsched_cb {
	s16 lambda_1000; /* values range from min_lambda * 100 to max_lambda * 100 */
	u32 last_lambda_update;
};

static struct blestsched_priv *blestsched_get_priv(const struct tcp_sock *tp)
{
	return (struct blestsched_priv *)&tp->mptcp->mptcp_sched[0];
}

static struct blestsched_cb *blestsched_get_cb(const struct tcp_sock *tp)
{
	return (struct blestsched_cb *)&tp->mpcb->mptcp_sched[0];
}

static void blestsched_update_lambda(struct sock *meta_sk, struct sock *sk)
{
	struct blestsched_cb *blest_cb = blestsched_get_cb(tcp_sk(meta_sk));
	struct blestsched_priv *blest_p = blestsched_get_priv(tcp_sk(sk));

	if (tcp_jiffies32 - blest_cb->last_lambda_update < usecs_to_jiffies(blest_p->min_srtt_us >> 3))
		return;

	/* if there have been retransmissions of packets of the slow flow
	 * during the slow flows last RTT => increase lambda
	 * otherwise decrease
	 */
	if (tcp_sk(meta_sk)->retrans_stamp) {
		/* need to slow down on the slow flow */
		blest_cb->lambda_1000 += dyn_lambda_bad;
	} else {
		/* use the slow flow more */
		blest_cb->lambda_1000 -= dyn_lambda_good;
	}

	/* cap lambda_1000 to its value range */
	blest_cb->lambda_1000 = min_t(s16, blest_cb->lambda_1000, max_lambda * 100);
	blest_cb->lambda_1000 = max_t(s16, blest_cb->lambda_1000, min_lambda * 100);

	blest_cb->last_lambda_update = tcp_jiffies32;
}

/* how many bytes will sk send during the rtt of another, slower flow? */
static u32 blestsched_estimate_bytes(struct sock *sk, u32 time_8)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct blestsched_priv *blest_p = blestsched_get_priv(tp);
	struct blestsched_cb *blest_cb = blestsched_get_cb(mptcp_meta_tp(tp));
	u32 avg_rtt, num_rtts, ca_cwnd, packets;

	avg_rtt = (blest_p->min_srtt_us + blest_p->max_srtt_us) / 2;
	if (avg_rtt == 0)
		num_rtts = 1; /* sanity */
	else
		num_rtts = (time_8 / avg_rtt) + 1; /* round up */

	/* during num_rtts, how many bytes will be sent on the flow?
	 * assumes for simplification that Reno is applied as congestion-control
	 */
	if (tp->snd_ssthresh == TCP_INFINITE_SSTHRESH) {
		/* we are in initial slow start */
		if (num_rtts > 16)
			num_rtts = 16; /* cap for sanity */
		packets = tp->snd_cwnd * ((1 << num_rtts) - 1); /* cwnd + 2*cwnd + 4*cwnd */
	} else {
		ca_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh + 1); /* assume we jump to CA already */
		packets = (ca_cwnd + (num_rtts - 1) / 2) * num_rtts;
	}

	return div_u64(((u64)packets) * tp->mss_cache * blest_cb->lambda_1000, 1000);
}

static u32 blestsched_estimate_linger_time(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct blestsched_priv *blest_p = blestsched_get_priv(tp);
	u32 estimate, slope, inflight, cwnd;

	inflight = tcp_packets_in_flight(tp) + 1; /* take into account the new one */
	cwnd = tp->snd_cwnd;

	if (inflight >= cwnd) {
		estimate = blest_p->max_srtt_us;
	} else {
		slope = blest_p->max_srtt_us - blest_p->min_srtt_us;
		if (cwnd == 0)
			cwnd = 1; /* sanity */
		estimate = blest_p->min_srtt_us + (slope * inflight) / cwnd;
	}

	return (tp->srtt_us > estimate) ? tp->srtt_us : estimate;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
 void Send_Info(struct sock *bestsk, struct sock *minsk, struct sock *meta_sk, int Lb) {

	/*************************************
	Pid: Path Identity : Source IP address + Source Tcp Port + Destination IP Address + Destination Tcp Port
	CWND: Window Size
	sRTT: Smoothed Round-Trip Time
	Th: Throughput
	Ds: Delivered Segments
	Te: Time elapsed
	Gp: Goodput
	Fs: In-flight segments
	Bo: Sender Buffer Occupancy
	Ts: Timestamp
	Lb: Label
 	cSS: current sub-session
	fSS: fast sub-session
	GS: MPTCP global session
	**************************************/
	 
	ktime_t curent_time = ktime_get();	
	s64 Ts = ktime_to_ns(curent_time);
	
	
	/*********************************   variables of best sk   *********************************/

	struct inet_sock *inetinfo_cSS = inet_sk(bestsk);	

	u64 cwnd_cSS, sRtt_cSS, Th_cSS, Fs_cSS, Bo_cSS, Ds_cSS, Te_cSS, Gp_cSS;
	cwnd_cSS=sRtt_cSS=Th_cSS=Fs_cSS=Bo_cSS=Ds_cSS=Te_cSS=Gp_cSS=0;
	u32 mss_cSS = tcp_current_mss(bestsk);
	
        if (tcp_sk(bestsk)->snd_cwnd) cwnd_cSS=tcp_sk(bestsk)->snd_cwnd;
	if (tcp_sk(bestsk)->srtt_us) sRtt_cSS=tcp_sk(bestsk)->srtt_us;
	if (tcp_sk(bestsk)->snd_cwnd  && tcp_sk(bestsk)->srtt_us)  Th_cSS=(tcp_sk(bestsk)->snd_cwnd*mss_cSS*8)/tcp_sk(bestsk)->srtt_us;
	if (tcp_sk(bestsk)->rate_delivered) Ds_cSS=tcp_sk(bestsk)->rate_delivered;
	if (tcp_sk(bestsk)->rate_interval_us) Te_cSS=tcp_sk(bestsk)->rate_interval_us;	
	if (tcp_sk(bestsk)->rate_delivered  && tcp_sk(bestsk)->rate_interval_us)  Gp_cSS=(tcp_sk(bestsk)->rate_delivered*mss_cSS*8)/tcp_sk(bestsk)->rate_interval_us;
	if (tcp_packets_in_flight(tcp_sk(bestsk))) Fs_cSS=tcp_packets_in_flight(tcp_sk(bestsk));
	if (bestsk->sk_sndbuf) Bo_cSS=bestsk->sk_wmem_queued;
	
	/*********************************   variables of min sk   *********************************/
	
	struct inet_sock *inetinfo_fSS = inet_sk(minsk);
	
	u64 cwnd_fSS, sRtt_fSS, Th_fSS, Fs_fSS, Bo_fSS, Ds_fSS, Te_fSS, Gp_fSS;
	cwnd_fSS=sRtt_fSS=Th_fSS=Fs_fSS=Bo_fSS=Ds_fSS=Te_fSS=Gp_fSS=0;
	u32 mss_fSS = tcp_current_mss(minsk);
	
        if (tcp_sk(minsk)->snd_cwnd) cwnd_fSS=tcp_sk(minsk)->snd_cwnd;
	if (tcp_sk(minsk)->srtt_us) sRtt_fSS=tcp_sk(minsk)->srtt_us;
	if (tcp_sk(minsk)->snd_cwnd  && tcp_sk(minsk)->srtt_us)  Th_fSS=(tcp_sk(minsk)->snd_cwnd*mss_fSS*8)/tcp_sk(minsk)->srtt_us;
	if (tcp_sk(minsk)->rate_delivered) Ds_fSS=tcp_sk(minsk)->rate_delivered;
	if (tcp_sk(minsk)->rate_interval_us) Te_fSS=tcp_sk(minsk)->rate_interval_us;	
	if (tcp_sk(minsk)->rate_delivered  && tcp_sk(minsk)->rate_interval_us)  Gp_fSS=(tcp_sk(minsk)->rate_delivered*mss_fSS*8)/tcp_sk(minsk)->rate_interval_us;
	if (tcp_packets_in_flight(tcp_sk(minsk))) Fs_fSS=tcp_packets_in_flight(tcp_sk(minsk));
	if (minsk->sk_sndbuf) Bo_fSS=minsk->sk_wmem_queued;
	
	/*********************************   variables of meta sk   *********************************/

	struct inet_sock *inetinfo_GS = inet_sk(meta_sk);

	u64 cwnd_GS, srtt_GS, Fs_GS, Bo_GS;
	cwnd_GS=srtt_GS=Fs_GS=Bo_GS=0;
	
	if (tcp_sk(meta_sk)->snd_cwnd) cwnd_GS=tcp_sk(meta_sk)->snd_wnd;
	if (tcp_sk(meta_sk)->srtt_us) srtt_GS=tcp_sk(meta_sk)->srtt_us;
	if (tcp_packets_in_flight(tcp_sk(meta_sk))) Fs_GS=tcp_packets_in_flight(tcp_sk(meta_sk));
	if (meta_sk->sk_wmem_queued) Bo_GS=meta_sk->sk_wmem_queued;

	printk(" %pI4+%pI4,%u,%u,%u,%u,%u,%u,%u,%u,%pI4+%pI4,%u,%u,%u,%u,%u,%u,%u,%u,%pI4+%pI4,%u,%u,%u,%u,%lld,%u\n", &inetinfo_cSS->inet_saddr, &inetinfo_cSS->inet_daddr, cwnd_cSS, sRtt_cSS, Th_cSS,  Ds_cSS, Te_cSS, Gp_cSS, Fs_cSS, Bo_cSS, &inetinfo_fSS->inet_saddr, &inetinfo_fSS->inet_daddr, cwnd_fSS, sRtt_fSS, Th_fSS, Ds_fSS, Te_fSS, Gp_fSS, Fs_fSS, Bo_fSS, &inetinfo_GS->inet_saddr, &inetinfo_GS->inet_daddr, cwnd_GS, srtt_GS, Fs_GS, Bo_GS, (long long)Ts, Lb);
}
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

/* This is the BLEST scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy or the currently best
 * subflow is estimated to possibly cause HoL-blocking, NULL is returned.
 */
struct sock *blest_get_available_subflow(struct sock *meta_sk, struct sk_buff *skb,
					 bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *bestsk, *minsk = NULL;
	struct tcp_sock *meta_tp, *besttp;
	struct mptcp_tcp_sock *mptcp;
	struct blestsched_priv *blest_p;
	u32 min_srtt = U32_MAX;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sub(mpcb, mptcp) {
			bestsk = mptcp_to_sock(mptcp);

			if (tcp_sk(bestsk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(bestsk, skb, zero_wnd_test))
				return bestsk;
		}
	}

	/* First, find the overall best subflow */
	mptcp_for_each_sub(mpcb, mptcp) {
		bestsk = mptcp_to_sock(mptcp);
		besttp = tcp_sk(bestsk);
		blest_p = blestsched_get_priv(besttp);

		/* Set of states for which we are allowed to send data */
		if (!mptcp_sk_can_send(bestsk))
			continue;

		/* We do not send data on this subflow unless it is
		 * fully established, i.e. the 4th ack has been received.
		 */
		if (besttp->mptcp->pre_established)
			continue;

		blest_p->min_srtt_us = min(blest_p->min_srtt_us, besttp->srtt_us);
		blest_p->max_srtt_us = max(blest_p->max_srtt_us, besttp->srtt_us);

		/* record minimal rtt */
		if (besttp->srtt_us < min_srtt) {
			min_srtt = besttp->srtt_us;
			minsk = bestsk;
		}
	}

	/* find the current best subflow according to the default scheduler */
	bestsk = get_available_subflow(meta_sk, skb, zero_wnd_test);

	/* if we decided to use a slower flow, we have the option of not using it at all */
	if (bestsk && minsk && bestsk != minsk) {
		u32 slow_linger_time, fast_bytes, slow_inflight_bytes, slow_bytes, avail_space;
		u32 buffered_bytes = 0;

		meta_tp = tcp_sk(meta_sk);
		besttp = tcp_sk(bestsk);

		blestsched_update_lambda(meta_sk, bestsk);

		/* if we send this SKB now, it will be acked in besttp->srtt seconds
		 * during this time: how many bytes will we send on the fast flow?
		 */
		slow_linger_time = blestsched_estimate_linger_time(bestsk);
		fast_bytes = blestsched_estimate_bytes(minsk, slow_linger_time);

		if (skb)
			buffered_bytes = skb->len;

		/* is the required space available in the mptcp meta send window?
		 * we assume that all bytes inflight on the slow path will be acked in besttp->srtt seconds
		 * (just like the SKB if it was sent now) -> that means that those inflight bytes will
		 * keep occupying space in the meta window until then
		 */
		slow_inflight_bytes = besttp->write_seq - besttp->snd_una;
		slow_bytes = buffered_bytes + slow_inflight_bytes; // bytes of this SKB plus those in flight already

		avail_space = (slow_bytes < meta_tp->snd_wnd) ? (meta_tp->snd_wnd - slow_bytes) : 0;

		if (fast_bytes > avail_space) {
			/* sending this SKB on the slow flow means
			 * we wouldn't be able to send all the data we'd like to send on the fast flow
			 * so don't do that
			 */
			/* ADD */Send_Info(bestsk,minsk,meta_sk,0);
			return NULL;
		}
	}
	/* ADD */if (bestsk && minsk) Send_Info(bestsk,minsk,meta_sk,1);
	return bestsk;
}

static void blestsched_init(struct sock *sk)
{
	struct blestsched_priv *blest_p = blestsched_get_priv(tcp_sk(sk));
	struct blestsched_cb *blest_cb = blestsched_get_cb(tcp_sk(mptcp_meta_sk(sk)));

	blest_p->last_rbuf_opti = tcp_jiffies32;
	blest_p->min_srtt_us = U32_MAX;
	blest_p->max_srtt_us = 0;

	if (!blest_cb->lambda_1000) {
		blest_cb->lambda_1000 = lambda * 100;
		blest_cb->last_lambda_update = tcp_jiffies32;
	}
}

static struct mptcp_sched_ops mptcp_sched_blest = {
	.get_subflow = blest_get_available_subflow,
	.next_segment = mptcp_next_segment,
	.init = blestsched_init,
	.name = "blest_log",
	.owner = THIS_MODULE,
};

static int __init blest_register(void)
{
	BUILD_BUG_ON(sizeof(struct blestsched_priv) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct blestsched_cb) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_blest))
		return -1;

	return 0;
}

static void blest_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_blest);
}

module_init(blest_register);
module_exit(blest_unregister);

MODULE_AUTHOR("Simone Ferlin, Daniel Weber");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BLEST scheduler for MPTCP, based on default minimum RTT scheduler");
MODULE_VERSION("0.95");
