#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <net/tcp.h>

// Maximum number of probes
#define MAX_PROBES 10

static struct kretprobe probes[MAX_PROBES];	// Probe handles
int inside_tcp = 0;	// Global to keep track of recv inside TCP or not

struct args {
	struct msghdr *msg;
	int data_len;
	struct iov_iter *msg_iter;
};

// static int secure_tcp_seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
// {
// 	// struct args *data;
// 	// data = (struct args *)ri->data;
// 	unsigned int retval = regs_return_value(regs);
// 	printk(KERN_INFO "%s returned %u\n", "secure_tcp_seq", retval);
// 	return 0;
// }

static int tcp_connect_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock *sk = (void *)regs_get_kernel_argument(regs, 0);
	struct tcp_sock *tp = tcp_sk(sk);
	printk(KERN_INFO "%s: SYN: %u\n", "tcp_connect", tp->write_seq);
	return 0;
}

static int tcp_v4_init_seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int retval = regs_return_value(regs);
	printk(KERN_INFO "%s: ACK: %u\n", "tcp_v4_init_seq", retval);
	return 0;
}

static int tcp_sendmsg_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct iov_iter msg_iter_backup;
	struct msghdr *msg = (void*)regs_get_kernel_argument(regs, 1);
	size_t size = regs_get_kernel_argument(regs, 2);

	if (msg->msg_iter.iter_type == 0) // USERBUF
	{
		char* membuf = msg->msg_iter.__ubuf_iovec.iov_base;
		for (int i = 0; i < size; i++)
			membuf[i] ^= 'Z';
		printk(KERN_INFO "membuf: %s\n", membuf);
	}

	return 0;
}

static int tcp_recvmsg_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	inside_tcp = 1;
	printk(KERN_INFO "tcp_recvmsg: lock\n");
	return 0;
}

static int tcp_recvmsg_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	inside_tcp = 0;
	printk(KERN_INFO "tcp_recvmsg: unlock\n");
	return 0;
}

static int skb_copy_datagram_iter_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (inside_tcp == 0)
		return 0;

	int size, offset;
	unsigned long tmp;
	struct sk_buff* skb;
	struct iov_iter *msg_iter;
	struct args *data;

	data = (struct args *)ri->data;

	tmp		= regs_get_kernel_argument(regs, 0);
	if (tmp != 0) { skb = (struct sk_buff*)tmp; }
	offset	= regs_get_kernel_argument(regs, 1);
	tmp 	= regs_get_kernel_argument(regs, 2);
	if (tmp != 0) { msg_iter = (struct iov_iter*)tmp; }
	size	= regs_get_kernel_argument(regs, 3);

	data->data_len = size;
	data->msg_iter = msg_iter;

	char *buffer = kmalloc(size, GFP_ATOMIC);
	skb_copy_bits(skb, offset, buffer, size);
	for (int i = 0; i < size; i++)
		buffer[i] ^= 'Z';
	skb_store_bits(skb, offset, buffer, size);
	printk("skb_copy_datagram_iter: [%d] %s\n", size, buffer);

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
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n", (*probe).kp.symbol_name, (*probe).kp.addr);
}

static int __init kretprobe_init(void)
{
	int i;
	for (i = 0; i < MAX_PROBES; i++) { probes[i].data_size = 0; }
	i = 0;
	//register_probe(&probes[i++], "secure_tcp_seq", &secure_tcp_seq_ret_handler, NULL);		// Generates SEQ/ACK numbers
	register_probe(&probes[i++], "tcp_connect", NULL, &tcp_connect_ent_handler);			// SYN
	register_probe(&probes[i++], "tcp_v4_init_seq", &tcp_v4_init_seq_ret_handler, NULL);	// SYN-ACK
	register_probe(&probes[i++], "tcp_sendmsg", NULL, &tcp_sendmsg_ent_handler);			// Sent data
	register_probe(&probes[i++], "tcp_recvmsg", &tcp_recvmsg_ret_handler, &tcp_recvmsg_ent_handler); 	// Received data boundary
	register_probe(&probes[i++], "skb_copy_datagram_iter", NULL, &skb_copy_datagram_iter_ent_handler);  // Received data
	return 0;
}

static void __exit kretprobe_exit(void)
{
	int i;
	for (i = 0; probes[i].data_size != 0; i++)
	{
		unregister_kretprobe(&(probes[i]));
		printk(KERN_INFO "kretprobe at %p unregistered\n", probes[i].kp.addr);

		/* nmissed > 0 suggests that maxactive was set too low. */
		printk(KERN_INFO "Missed probing %d instances of %s\n", probes[i].nmissed, probes[i].kp.symbol_name);
	}
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
