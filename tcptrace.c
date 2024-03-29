#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <net/tcp.h>
#include <net/secure_seq.h>

// Maximum number of probes
#define MAX_PROBES 10

static struct kretprobe probes[MAX_PROBES];	// Probe handles
int inside_tcp = 0;	// Global to keep track of recv inside TCP or not

struct args {
	struct msghdr *msg;
	int data_len;
	struct iov_iter *msg_iter;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
};

// POC, obviously not real
bool is_prime_number(u32 value)
{
	if ( (value %2 == 0) || (value % 3 == 0) || (value % 5 == 0) ||
		(value %7 == 0) || (value % 11 == 0) || (value % 13 == 0))
		{
			return false;
		}
	return true;
}

static int secure_tcp_seq_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct args *data;
	data = (struct args *)ri->data;
	data->saddr = (__be32)regs_get_kernel_argument(regs, 0);
	data->daddr = (__be32)regs_get_kernel_argument(regs, 1);
	data->sport = (__be16)regs_get_kernel_argument(regs, 2);
	data->dport = (__be16)regs_get_kernel_argument(regs, 3);
	return 0;
}

static int secure_tcp_seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct args *data;
	data = (struct args *)ri->data;
	unsigned long retval = regs_return_value(regs);
	// disable_kretprobe(&(probes[0])); // Buggy on some kernels?
	while (!is_prime_number(retval))
	{
		// This should be replaced. Just generate a suitable prime number
		retval = secure_tcp_seq(data->saddr, data->daddr, data->sport, data->dport);
	}
	// enable_kretprobe(&(probes[0])); // Buggy on some kernels?
	regs_set_return_value(regs, retval);
	//printk(KERN_INFO "%s returned %u\n", "secure_tcp_seq", (u32)retval);
	return 0;
}

// static void tcp_options_write(struct tcphdr *th, struct tcp_sock *tp,
// 			      struct tcp_out_options *opts)
static int tcp_options_write_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long tmp = regs_get_kernel_argument(regs, 0);
	if (tmp != 0)
	{
		struct tcphdr *th = (struct tcphdr *)tmp;
		th->res1 |= 4; // Should set a reserved bit
		printk(KERN_INFO "%s: TCP Header, res1: %d\n", "tcp_options_write", th->res1);
	}
	else
	{
		printk(KERN_INFO "%s: TCP Header, No res:(\n", "tcp_options_write");
	}
	
	return 0;
}

// int tcp_connect(struct sock *sk);
static int tcp_connect_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock *sk = (void *)regs_get_kernel_argument(regs, 0);
	struct tcp_sock *tp = tcp_sk(sk);
	printk(KERN_INFO "SYN (sent): %u\n", tp->write_seq);
	return 0;
}

// void tcp_send_ack(struct sock *sk);
static int tcp_send_ack_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock *sk = (struct sock *)regs_get_kernel_argument(regs, 0);
	printk(KERN_INFO "ACK (recv): %u\n", (tcp_sk(sk)->rcv_nxt)-1);
	// (tcp_sk(sk)->rack.end_seq)-1, 
	return 0;
}

// static u32 tcp_v4_init_seq(const struct sk_buff *skb)
// static int tcp_v4_init_seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
// {
// 	unsigned int retval = regs_return_value(regs);
// 	printk(KERN_INFO "%s: ACK (sent): %u\n", "tcp_v4_init_seq", retval);
// 	// dump_stack();
// 	return 0;
// }

// struct sk_buff *tcp_make_synack(const struct sock *sk, struct dst_entry *dst,
// 				struct request_sock *req,
// 				struct tcp_fastopen_cookie *foc,
// 				enum tcp_synack_type synack_type,
// 				struct sk_buff *syn_skb);
static int tcp_make_synack_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct request_sock* req = (struct request_sock *)regs_get_kernel_argument(regs, 2);
	u32 seq = tcp_rsk(req)->snt_isn;
	u32 ack_seq = tcp_rsk(req)->rcv_nxt;
	printk(KERN_INFO "ACK (sent): %u\n", seq);
	printk(KERN_INFO "SYN (recv): %u\n", ack_seq-1);
	return 0;
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
static int tcp_sendmsg_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct msghdr *msg 	= (struct msghdr *)regs_get_kernel_argument(regs, 1);
	size_t size 		= regs_get_kernel_argument(regs, 2);

	if (msg->msg_iter.iter_type == 0) // USERBUF
	{
		// Need to check if this is valid memory
		char* membuf = msg->msg_iter.__ubuf_iovec.iov_base;
		// for (int i = 0; i < size; i++)
		// 	membuf[i] ^= 'Z';
		printk(KERN_INFO "DATA (sent):[%lu]%s\n", size, membuf);
	}

	return 0;
}

// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len);
static int tcp_recvmsg_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// Should be a semaphore or a real kernel lock
	inside_tcp = 1;
	printk(KERN_INFO "tcp_recvmsg: lock\n");

	//struct iov_iter *msg_iter = &(msg->msg_iter)
	// if (msg_iter.iter_type == 0) // USER_BUF
	// {
	// }
	return 0;
}

static int tcp_recvmsg_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// Should be a semaphore or a real kernel lock
	inside_tcp = 0;
	printk(KERN_INFO "tcp_recvmsg: unlock\n");
	return 0;
}

// int skb_copy_datagram_iter(const struct sk_buff *from, int offset, struct iov_iter *to, int size);
static int skb_copy_datagram_iter_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// Should be a semaphore or a real kernel lock
	if (inside_tcp == 0)
		return 0;

	int size, offset;
	unsigned long tmp;
	struct sk_buff* skb;
	struct iov_iter *msg_iter;
	// struct args *data;

	// data = (struct args *)ri->data;

	tmp		= regs_get_kernel_argument(regs, 0);
	if (tmp != 0) { skb = (struct sk_buff*)tmp; }

	// Check if we are doing encryption or not
	printk(KERN_INFO "DATA (recv): header reserved bit: %u\n", tcp_hdr(skb)->res1);
	if (tcp_hdr(skb)->res1 & 4)
	{
		offset	= regs_get_kernel_argument(regs, 1);
		tmp 	= regs_get_kernel_argument(regs, 2);
		if (tmp != 0) { msg_iter = (struct iov_iter*)tmp; }
		size	= regs_get_kernel_argument(regs, 3);

		// data->data_len = size;
		// data->msg_iter = msg_iter;

		// This is a temporary check for testing. Need to mark in the TCP header to decrypt/encrypt
		// Maybes:
		// const struct iphdr *iph = (const struct iphdr *)skb->data;
		// struct tcphdr *th = (struct tcphdr *)(skb->data + (iph->ihl << 2));
		// 
		// struct tcphdr *th = tcp_hdr(skb);
		if (msg_iter->iter_type == 0) // USER_BUF
		{
			char *buffer = kmalloc(size, GFP_ATOMIC);
			skb_copy_bits(skb, offset, buffer, size);
			// Todo: Encryption here when ready!
			// for (int i = 0; i < size; i++)
			// 	buffer[i] ^= 'Z';
			skb_store_bits(skb, offset, buffer, size);
			printk("DATA (recv):[%d]%s\n", size, buffer);
			kfree(buffer);
		}
	}
	return 0;
}

void register_probe(struct kretprobe *probe, char *func_name, int(*ret_handler)(struct kretprobe_instance*, struct pt_regs*),int(*ent_handler)(struct kretprobe_instance*, struct pt_regs*))
{
	int ret;
	(*probe).kp.symbol_name = func_name;
	if (ent_handler != NULL)
		(*probe).entry_handler = ent_handler;
	if (ret_handler != NULL)
		(*probe).handler = ret_handler;
	(*probe).data_size = sizeof(struct args);
	(*probe).maxactive = 20;
	ret = register_kretprobe(probe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
		(*probe).data_size = 0;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n", (*probe).kp.symbol_name, (*probe).kp.addr);
}

static int __init kretprobe_init(void)
{
	int i;
	for (i = 0; i < MAX_PROBES; i++) { probes[i].data_size = 0; }
	i = 0;
	register_probe(&probes[i++], "secure_tcp_seq", &secure_tcp_seq_ret_handler, &secure_tcp_seq_ent_handler);		// Generates SEQ/ACK numbers
	register_probe(&probes[i++], "tcp_connect", NULL, &tcp_connect_ent_handler);					// !SYN (sent)
	register_probe(&probes[i++], "tcp_make_synack", NULL, &tcp_make_synack_ent_handler);			// !ACK (sent) and SYN (recv)
	register_probe(&probes[i++], "tcp_send_ack", NULL, &tcp_send_ack_ent_handler);					// !ACK (recv)

	// Got all the data
	register_probe(&probes[i++], "tcp_sendmsg", NULL, &tcp_sendmsg_ent_handler);						// !DATA: Sent
	register_probe(&probes[i++], "tcp_recvmsg", &tcp_recvmsg_ret_handler, &tcp_recvmsg_ent_handler); 	// !DATA: Received data boundary
	register_probe(&probes[i++], "skb_copy_datagram_iter", NULL, &skb_copy_datagram_iter_ent_handler);  // !DATA: Recv

	// Modify headers
	// nogood, called by __tcp_transmit_skb
	register_probe(&probes[i++], "tcp_options_write.constprop.0", NULL, &tcp_options_write_ent_handler);
	return 0;
}

static void __exit kretprobe_exit(void)
{
	int i;
	for (i = 0; i < MAX_PROBES; i++)
	{
		if (probes[i].data_size != 0)
		{
			unregister_kretprobe(&(probes[i]));
			printk(KERN_INFO "kretprobe at %p unregistered\n", probes[i].kp.addr);
	
			/* nmissed > 0 suggests that maxactive was set too low. */
			printk(KERN_INFO "Missed probing %d instances of %s\n", probes[i].nmissed, probes[i].kp.symbol_name);
		}
	}
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
