/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 1;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 1;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

struct rrsched_priv {
	unsigned char quota;
};

static struct rrsched_priv *rrsched_get_priv(const struct tcp_sock *tp)
{
	return (struct rrsched_priv *)&tp->mptcp->mptcp_sched[0];
}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_rr_is_available(const struct sock *sk, const struct sk_buff *skb,
				  bool zero_wnd_test, bool cwnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int space, in_flight;

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}

	if (!cwnd_test)
		goto zero_wnd_test;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

zero_wnd_test:
	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_rr_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
 void getInfo(struct sock *bestsk, struct sock *minsk, struct sock *meta_sk, int c) {

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
	Sl: Segment Loss
	Rt: Retransmission
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
	u32 tcp_sport_cSS, tcp_dport_cSS;
	tcp_sport_cSS = ntohs(inetinfo_cSS->inet_sport);
	tcp_dport_cSS = ntohs(inetinfo_cSS->inet_dport);	

	u64 cwnd_cSS, sRtt_cSS, Th_cSS, Fs_cSS, Bo_cSS, Sl_cSS, Rt_cSS, Ds_cSS, Te_cSS, Gp_cSS;
	cwnd_cSS=sRtt_cSS=Th_cSS=Fs_cSS=Bo_cSS=Sl_cSS=Rt_cSS=Ds_cSS=Te_cSS=Gp_cSS=0;
	u32 mss_cSS = tcp_current_mss(bestsk);
	
        if (tcp_sk(bestsk)->snd_cwnd) cwnd_cSS=tcp_sk(bestsk)->snd_cwnd;
	if (tcp_sk(bestsk)->srtt_us) sRtt_cSS=tcp_sk(bestsk)->srtt_us;
	if (tcp_sk(bestsk)->snd_cwnd  && tcp_sk(bestsk)->srtt_us)  Th_cSS=(tcp_sk(bestsk)->snd_cwnd*mss_cSS*8)/tcp_sk(bestsk)->srtt_us;
	if (tcp_packets_in_flight(tcp_sk(bestsk))) Fs_cSS=tcp_packets_in_flight(tcp_sk(bestsk));
	if (bestsk->sk_sndbuf) Bo_cSS=bestsk->sk_wmem_queued;
	if (tcp_sk(bestsk)->lost) Sl_cSS=tcp_sk(bestsk)->lost;
	if (tcp_sk(bestsk)->retrans_out) Rt_cSS=tcp_sk(bestsk)->retrans_out;
	if (tcp_sk(bestsk)->rate_delivered) Ds_cSS=tcp_sk(bestsk)->rate_delivered;
	if (tcp_sk(bestsk)->rate_interval_us) Te_cSS=tcp_sk(bestsk)->rate_interval_us;	
	if (tcp_sk(bestsk)->rate_delivered  && tcp_sk(bestsk)->rate_interval_us)  Gp_cSS=(tcp_sk(bestsk)->rate_delivered*mss_cSS*8)/tcp_sk(bestsk)->rate_interval_us;		

	
	/*********************************   variables of min sk   *********************************/
	
	struct inet_sock *inetinfo_fSS = inet_sk(minsk);
	u32 tcp_sport_fSS, tcp_dport_fSS;
	tcp_sport_fSS = ntohs(inetinfo_fSS->inet_sport);
	tcp_dport_fSS = ntohs(inetinfo_fSS->inet_dport);
	
	u64 cwnd_fSS, sRtt_fSS, Th_fSS, Fs_fSS, Bo_fSS, Sl_fSS, Rt_fSS, Ds_fSS, Te_fSS, Gp_fSS;
	cwnd_fSS=sRtt_fSS=Th_fSS=Fs_fSS=Bo_fSS=Sl_fSS=Rt_fSS=Ds_fSS=Te_fSS=Gp_fSS=0;
	u32 mss_fSS = tcp_current_mss(minsk);
	
        if (tcp_sk(minsk)->snd_cwnd) cwnd_fSS=tcp_sk(minsk)->snd_cwnd;
	if (tcp_sk(minsk)->srtt_us) sRtt_fSS=tcp_sk(minsk)->srtt_us;
	if (tcp_sk(minsk)->snd_cwnd  && tcp_sk(minsk)->srtt_us)  Th_fSS=(tcp_sk(minsk)->snd_cwnd*mss_fSS*8)/tcp_sk(minsk)->srtt_us;
	if (tcp_packets_in_flight(tcp_sk(minsk))) Fs_fSS=tcp_packets_in_flight(tcp_sk(minsk));
	if (minsk->sk_sndbuf) Bo_fSS=minsk->sk_wmem_queued;
	if (tcp_sk(minsk)->lost) Sl_fSS=tcp_sk(minsk)->lost;
	if (tcp_sk(minsk)->retrans_out) Rt_fSS=tcp_sk(minsk)->retrans_out;
	if (tcp_sk(minsk)->rate_delivered) Ds_fSS=tcp_sk(minsk)->rate_delivered;
	if (tcp_sk(minsk)->rate_interval_us) Te_fSS=tcp_sk(minsk)->rate_interval_us;	
	if (tcp_sk(minsk)->rate_delivered  && tcp_sk(minsk)->rate_interval_us)  Gp_fSS=(tcp_sk(minsk)->rate_delivered*mss_fSS*8)/tcp_sk(minsk)->rate_interval_us;
	
	/*********************************   variables of meta sk   *********************************/

	struct inet_sock *inetinfo_GS = inet_sk(meta_sk);
	u32 tcp_sport_GS, tcp_dport_GS;
	tcp_sport_GS = ntohs(inetinfo_GS->inet_sport);
	tcp_dport_GS = ntohs(inetinfo_GS->inet_dport);

	u64 cwnd_GS, srtt_GS, Fs_GS, Bo_GS;
	cwnd_GS=srtt_GS=Fs_GS=Bo_GS=0;
	
	if (tcp_sk(meta_sk)->snd_cwnd) cwnd_GS=tcp_sk(meta_sk)->snd_wnd;
	if (tcp_sk(meta_sk)->srtt_us) srtt_GS=tcp_sk(meta_sk)->srtt_us;
	if (tcp_packets_in_flight(tcp_sk(meta_sk))) Fs_GS=tcp_packets_in_flight(tcp_sk(meta_sk));
	if (meta_sk->sk_wmem_queued) Bo_GS=meta_sk->sk_wmem_queued;

	printk(" %pI4+%u+%pI4+%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%pI4+%u+%pI4+%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%pI4+%u+%pI4+%u,%u,%u,%u,%u,%lld,%u\n", &inetinfo_cSS->inet_saddr, tcp_sport_cSS, &inetinfo_cSS->inet_daddr, tcp_dport_cSS, cwnd_cSS, sRtt_cSS, Th_cSS, Fs_cSS, Bo_cSS, Sl_cSS, Rt_cSS, Ds_cSS, Te_cSS, Gp_cSS, &inetinfo_fSS->inet_saddr, tcp_sport_fSS, &inetinfo_fSS->inet_daddr, tcp_dport_fSS, cwnd_fSS, sRtt_fSS, Th_fSS, Fs_fSS, Bo_fSS, Sl_fSS, Rt_fSS, Ds_fSS, Te_fSS, Gp_fSS, &inetinfo_GS->inet_saddr, tcp_sport_GS, &inetinfo_GS->inet_daddr, tcp_dport_GS, cwnd_GS, srtt_GS, Fs_GS, Bo_GS, (long long)Ts, Lb);
}
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* We just look for any subflow that is available */
static struct sock *rr_get_available_subflow(struct sock *meta_sk,
					     struct sk_buff *skb,
					     bool zero_wnd_test)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk = NULL, *bestsk = NULL, *backupsk = NULL;
	struct mptcp_tcp_sock *mptcp;
	/*ADD*/u32 min_srtt = U32_MAX;
	/*Add*/struct sock *minsk = NULL;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_rr_is_available(sk, skb, zero_wnd_test, true))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sub(mpcb, mptcp) {
		struct tcp_sock *tp;

		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);

		if (!mptcp_rr_is_available(sk, skb, zero_wnd_test, true))
			continue;

		if (mptcp_rr_dont_reinject_skb(tp, skb)) {
			backupsk = sk;
			continue;
		}
		/*ADD*//* record minimal rtt */
		/*ADD*/if (tp->srtt_us < min_srtt) {
		/*ADD*/	min_srtt = tp->srtt_us;
		/*ADD*/	minsk = sk;
		/*ADD*/}

		bestsk = sk;
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}
	/* ADD */if (sk && minsk) getInfo(sk,minsk,meta_sk,1);
	return sk;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_rr_next_segment(const struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb)
		*reinject = 1;
	else
		skb = tcp_send_head(meta_sk);
	return skb;
}

static struct sk_buff *mptcp_rr_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *choose_sk = NULL;
	struct mptcp_tcp_sock *mptcp;
	struct sk_buff *skb = __mptcp_rr_next_segment(meta_sk, reinject);
	unsigned char split = num_segments;
	unsigned char iter = 0, full_subs = 0;
	/*Add*/u32 min_srtt = U32_MAX;
	/*Add*/struct sock *minsk = NULL;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	if (*reinject) {
		*subsk = rr_get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;

		return skb;
	}

retry:

	/* First, we look for a subflow who is currently being used */
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct rrsched_priv *rr_p = rrsched_get_priv(tp_it);

		if (!mptcp_rr_is_available(sk_it, skb, false, cwnd_limited))
			continue;

		iter++;
		/*ADD*//* record minimal rtt */
		/*ADD*/if (tp_it->srtt_us < min_srtt) {
		/*ADD*/	min_srtt = tp_it->srtt_us;
		/*ADD*/	minsk = sk_it;
		/*ADD*/}

		/* Is this subflow currently being used? */
		if (rr_p->quota > 0 && rr_p->quota < num_segments) {
			split = num_segments - rr_p->quota;
			choose_sk = sk_it;
			goto found;
		}

		/* Or, it's totally unused */
		if (!rr_p->quota) {
			split = num_segments;
			choose_sk = sk_it;
		}

		/* Or, it must then be fully used  */
		if (rr_p->quota >= num_segments)
			full_subs++;
	}

	/* All considered subflows have a full quota, and we considered at
	 * least one.
	 */
	if (iter && iter == full_subs) {
		/* So, we restart this round by setting quota to 0 and retry
		 * to find a subflow.
		 */
		mptcp_for_each_sub(mpcb, mptcp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			struct rrsched_priv *rr_p = rrsched_get_priv(tp_it);

			if (!mptcp_rr_is_available(sk_it, skb, false, cwnd_limited))
				continue;

			rr_p->quota = 0;
		}

		goto retry;
	}

found:
	if (choose_sk) {
		unsigned int mss_now;
		struct tcp_sock *choose_tp = tcp_sk(choose_sk);
		struct rrsched_priv *rr_p = rrsched_get_priv(choose_tp);

		if (!mptcp_rr_is_available(choose_sk, skb, false, true))
			return NULL;

		*subsk = choose_sk;
		mss_now = tcp_current_mss(*subsk);
		*limit = split * mss_now;

		if (skb->len > mss_now)
			rr_p->quota += DIV_ROUND_UP(skb->len, mss_now);
		else
			rr_p->quota++;
		/* ADD */if (choose_sk && minsk) getInfo(choose_sk,minsk,meta_sk,1);
		return skb;
	}

	return NULL;
}

static struct mptcp_sched_ops mptcp_sched_rr = {
	.get_subflow = rr_get_available_subflow,
	.next_segment = mptcp_rr_next_segment,
	.name = "rr_log",
	.owner = THIS_MODULE,
};

static int __init rr_register(void)
{
	BUILD_BUG_ON(sizeof(struct rrsched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_rr))
		return -1;

	return 0;
}

static void rr_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_rr);
}

module_init(rr_register);
module_exit(rr_unregister);

MODULE_AUTHOR("Christoph Paasch");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ROUNDROBIN MPTCP");
MODULE_VERSION("0.89");
