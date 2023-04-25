#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/kallsyms.h>

#include <asm/current.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("anonymous");
MODULE_DESCRIPTION("Playing around with PID allocations");

struct pid **pid_list;

typedef void (* _free_pid)(struct pid *pid);
typedef struct pid* (* _alloc_pid)(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size);

_free_pid my_free_pid;
_alloc_pid my_alloc_pid;
int *my_pid_max;
int PID_LIST_COUNT;

struct pid_namespace *get_namespace(void) {
    struct pid_namespace *ns = NULL;
    ns = task_active_pid_ns(rcu_dereference(current->parent));
    if (!ns) {
        printk(KERN_INFO "[!] didnt get namespace\n");
        return NULL;
    }
    return ns;
}

void print_pid(struct pid* pid) {
    int n;
    if (pid != NULL) {
        for (n = pid->level; n >= 0; n--) {
            printk(KERN_INFO "[pid] %d", pid->numbers[n].nr);
        }
    }
}

void alloc_pids(void) {
    int i;
    struct pid_namespace *ns;
    struct pid *pid;

    if (pid_list) {
        ns = get_namespace();
        for (i = 0; i < PID_LIST_COUNT; i++) {
            pid = my_alloc_pid(ns, NULL, 0);
            if (IS_ERR(pid))
                continue;
            pid_list[i] = pid;
            print_pid(pid_list[i]);
        }
    }
}

void free_pids(void) {
    int i;
    struct pid *tmp;
    if (pid_list) {
        for (i = 0; i < PID_LIST_COUNT; i++) {
            tmp = (struct pid *)(pid_list[i]);
            if (tmp != NULL) {
                print_pid(tmp);
                my_free_pid(tmp);
            }
        }
        vfree(pid_list);
    }
}



int init_module(void) {
    printk(KERN_INFO "[+] pidtest init\n");

    my_free_pid  = (_free_pid)kallsyms_lookup_name("free_pid");
    my_alloc_pid = (_alloc_pid)kallsyms_lookup_name("alloc_pid");
    my_pid_max   = (int *)kallsyms_lookup_name("pid_max");
    PID_LIST_COUNT = *my_pid_max - 1000;
    pid_list     = (struct pid **)vmalloc(sizeof(struct pid *) * PID_LIST_COUNT);

    printk(KERN_INFO "pid_max: %d\n", *my_pid_max);

    if (!pid_list) {
        pr_err("Unable to allocate space for pid_list\n");
        return -EINVAL;
    }
    if (my_free_pid == 0) {
        pr_err("Unable to find free_pid\n");
        return -EINVAL;
    }
    if (my_alloc_pid == 0) {
        pr_err("Unable to find alloc_pid\n");
        return -EINVAL;
    }
    alloc_pids();
    return 0;
}

void cleanup_module(void) {
    free_pids();
    printk(KERN_INFO "[+] pidtest exit\n");
}
