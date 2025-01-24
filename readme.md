# Background
This project was born from a little curiousity on what control I can exert over a child process PID when `fork` is called.
After some digging, I wrote this kernel module that influences how many PIDs are allowed to be allocated and used.

# Compilation
```
make
```

# fork and getting a pid

`fork()` calls `_do_fork()`, which is definedhere: https://elixir.bootlin.com/linux/v5.6.3/source/kernel/fork.c#L2395

These lines seem to indicate at getting a pid:

	p = copy_process(NULL, trace, NUMA_NO_NODE, args);
    ...
	pid = get_task_pid(p, PIDTYPE_PID);

Looking inside of [copy_process](https://elixir.bootlin.com/linux/v5.6.3/source/kernel/fork.c#L1824):

	if (pid != &init_struct_pid) {
		pid = alloc_pid(p->nsproxy->pid_ns_for_children, args->set_tid,
				args->set_tid_size);
		if (IS_ERR(pid)) {
			retval = PTR_ERR(pid);
			goto bad_fork_cleanup_thread;
		}
	}

And then, in [alloc_pid](https://elixir.bootlin.com/linux/v5.6.3/source/kernel/pid.c#L160) the actual allocation:
    
    pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);

PIDs appear to be in a preallocated cache/space using `kmem_cache_alloc`. We can find a combo of `idir_init` for pids and pointing the "pid namespace" at this kmem cache:

    void __init pid_idr_init(void)
    {
        /* Verify no one has done anything silly: */
        BUILD_BUG_ON(PID_MAX_LIMIT >= PIDNS_ADDING);

        /* bump default and minimum pid_max based on number of cpus */
        pid_max = min(pid_max_max, max_t(int, pid_max,
                    PIDS_PER_CPU_DEFAULT * num_possible_cpus()));
        pid_max_min = max_t(int, pid_max_min,
                    PIDS_PER_CPU_MIN * num_possible_cpus());
        pr_info("pid_max: default: %u minimum: %u\n", pid_max, pid_max_min);

        idr_init(&init_pid_ns.idr);

        init_pid_ns.pid_cachep = KMEM_CACHE(pid,
                SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT);
    }

Where `KMEM_CACHE` is a macro: https://elixir.bootlin.com/linux/v5.6.3/source/include/linux/slab.h#L169

    #define KMEM_CACHE(__struct, __flags)					\
            kmem_cache_create(#__struct, sizeof(struct __struct),	\
                __alignof__(struct __struct), (__flags), NULL)

So we have found the memory where the PID structures seem to be stored at. It seems that idr_init is used to do the allocating, so lets look at that

# The IDR and ID Allocation
    /**
     * idr_alloc_cyclic() - Allocate an ID cyclically.
     * @idr: IDR handle.
     * @ptr: Pointer to be associated with the new ID.
     * @start: The minimum ID (inclusive).
     * @end: The maximum ID (exclusive).
     * @gfp: Memory allocation flags.
     *
     * Allocates an unused ID in the range specified by @nextid and @end.  If
     * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
     * callers to use @start + N as @end as long as N is within integer range.
     * The search for an unused ID will start at the last ID allocated and will
     * wrap around to @start if no free IDs are found before reaching @end.
     *
     * The caller should provide their own locking to ensure that two
     * concurrent modifications to the IDR are not possible.  Read-only
     * accesses to the IDR may be done under the RCU read lock or may
     * exclude simultaneous writers.
     *
     * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
     * or -ENOSPC if no free IDs could be found.
     */
    int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
    {
      u32 id = idr->idr_next;
      int err, max = end > 0 ? end - 1 : INT_MAX;

      if ((int)id < start)
        id = start;

      err = idr_alloc_u32(idr, ptr, &id, max, gfp);
      if ((err == -ENOSPC) && (id > start)) {
        id = start;
        err = idr_alloc_u32(idr, ptr, &id, max, gfp);
      }
      if (err)
        return err;

      idr->idr_next = id + 1;
      return id;
    }

From this, we can see that it increments a single ID at a time: `idr->idr_next = id + 1;`
