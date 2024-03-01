#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <net/tcp.h>

#define MAX_PROBES 10

static struct kretprobe probes[MAX_PROBES];

struct args {
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;
};

static int tcp_connect_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock *sk = (void *)regs_get_kernel_argument(regs, 0);
	struct tcp_sock *tp = tcp_sk(sk);
	printk(KERN_INFO "%s write_seq: %u\n", "tcp_connect", tp->write_seq);
	return 0;
}

static int tcp_v4_init_seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int retval = regs_return_value(regs);
	printk(KERN_INFO "%s returned %u\n", "tcp_v4_init_seq", retval);
	return 0;
}

static int secure_tcp_seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int retval = regs_return_value(regs);
	printk(KERN_INFO "%s returned %u\n", "secure_tcp_seq", retval);
	return 0;
}


static int tcp_v4_connect_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct args *data;
	data = (struct args *)ri->data;
	data->arg0 = regs_get_kernel_argument(regs, 0);
	return 0;
}

static int tcp_sendmsg_ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	printk(KERN_INFO "%s entered.\n", "tcp_sendmsg");
	char buffer[512];
	struct iov_iter msg_iter_backup;
	struct msghdr *msg = (void*)regs_get_kernel_argument(regs, 1);
	size_t size = regs_get_kernel_argument(regs, 2);

	if (size < 512)
	{
		msg_iter_backup = msg->msg_iter;
		_copy_from_iter(buffer, size, &(msg->msg_iter));
		msg->msg_iter = msg_iter_backup;
		buffer[size] = '\0';
		printk(KERN_INFO "%s [%lu]: %s\n", "tcp_sendmsg", size, buffer);
	}
	return 0;
}

static int tcp_v4_connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct args *data;
	data = (struct args *)ri->data;

	struct sock *sk = (void*)data->arg0;
	struct tcp_sock *tp = tcp_sk(sk);

	printk(KERN_INFO "%s write_seq: %u\n", "tcp_v4_connect", tp->write_seq);
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
	register_probe(&probes[i++], "tcp_v4_init_seq", &tcp_v4_init_seq_ret_handler, NULL);
	register_probe(&probes[i++], "secure_tcp_seq", &secure_tcp_seq_ret_handler, NULL);
	register_probe(&probes[i++], "tcp_v4_connect", &tcp_v4_connect_ret_handler, &tcp_v4_connect_ent_handler);
	register_probe(&probes[i++], "tcp_connect", NULL, &tcp_connect_ent_handler);
	register_probe(&probes[i++], "tcp_sendmsg_locked", NULL, &tcp_sendmsg_ent_handler);
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
