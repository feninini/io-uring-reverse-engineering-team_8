# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1

Continue with the list untill all functions used in each source are listed.


### c files 

# advise.c

| Source    | Library / Source Origin                    | Function utilized           | Time Used |
|-----------|---------------------------------------------|------------------------------|-----------|
| advise.c  | `fs/advice.c` or `mm/madvise.c`             | `do_madvise`                 | 1         |
|  | `include/linux/sched.h`                     | `current`                    | 1         |
|  | `include/linux/io_uring_types.h`            | `io_kiocb_to_cmd`            | 4         |
| | `include/linux/io_uring_types.h`            | `io_req_set_res`             | 2         |
|   | `include/linux/io_uring_types.h`            | `req_set_fail`               | 1         |
|   | `mm/fadvise.c`                              | `vfs_fadvise`                | 1         |
|   | `arch/x86/include/asm/barrier.h`            | `READ_ONCE`                  | 6         |
|   | `include/linux/kernel.h`                    | `WARN_ON_ONCE`               | 2         |
|   | *advise.c* (internal/self)                  | `io_madvise`                 | 1         |
|  | *advise.c* (internal/self)                  | `io_madvise_prep`            | 1         |
|  | *advise.c* (internal/self)                  | `io_fadvise`                 | 1         |
|  | *advise.c* (internal/self)                  | `io_fadvise_prep`            | 1         |
| | *advise.c* (internal/self)                  | `io_fadvise_force_async`     | 2         |

# alloc_cache.c

| Source         | Library / Source Origin                         | Function utilized         | Time Used |
|----------------|--------------------------------------------------|----------------------------|------------|
|  alloc_cache.c | `mm/util.c` or `include/linux/mm.h`             | `kvfree`                   | 1          |
|                | `mm/util.c` or `include/linux/mm.h`             | `kvmalloc_array`           | 1          |
|                | `mm/slab_common.c` or `include/linux/slab.h`    | `kmalloc`                  | 1          |
|                | `arch/x86/include/asm/string_64.h`              | `memset`                   | 1          |
|                | `include/linux/gfp.h`                           | `GFP_KERNEL`               | 1 (macro)  |
|                | *alloc_cache.c* (internal/self)                 | `io_alloc_cache_get`       | 1          |
|                | *alloc_cache.c* (internal/self)                 | `io_cache_alloc_new`       | 1          |

# cancel.c
| Source     | Library / Source Origin                | Function utilized            | Time Used |
|------------|-----------------------------------------|-------------------------------|-----------|
| cancel.c   | include/linux/io_uring_types.h         | io_kiocb_to_cmd               | 2         |
|            | include/linux/io_uring_types.h         | io_wq_current_is_worker       | 1         |
|            | include/linux/kernel.h                 | WARN_ON_ONCE                  | 1         |
|            | arch/x86/include/asm/barrier.h         | READ_ONCE                     | 4         |
|            | include/linux/spinlock.h               | spin_lock                     | 1         |
|            | include/linux/spinlock.h               | spin_unlock                   | 1         |
|            | include/linux/errno.h                  | -ENOENT                       | 4         |
|            | include/linux/errno.h                  | -EINVAL                       | 3         |
|            | include/linux/errno.h                  | -EALREADY                     | 1         |
|            | include/linux/list.h                   | list_for_each_entry           | 1         |
|            | kernel/io_uring/poll.c                 | io_poll_cancel                | 1         |
|            | kernel/io_uring/waitid.c               | io_waitid_cancel              | 1         |
|            | kernel/io_uring/futex.c                | io_futex_cancel               | 1         |
|            | kernel/io_uring/timeout.c              | io_timeout_cancel             | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_cancel_req_match           | 2         |
|            | kernel/io_uring/cancel.c (internal)    | io_cancel_cb                  | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_async_cancel_one           | 2         |
|            | kernel/io_uring/cancel.c (internal)    | io_try_cancel                 | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_async_cancel_prep          | 1         |
|            | kernel/io_uring/cancel.c (internal)    | __io_async_cancel             | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_async_cancel               | 1         |
|            | kernel/io_uring/submit.c               | io_ring_submit_lock           | 1         |
|            | kernel/io_uring/submit.c               | io_ring_submit_unlock         | 1         |
|            | kernel/io_uring/workqueue.c            | io_wq_cancel_cb               | 1         |
|            | include/linux/atomic/atomic-instrumented.h | atomic_inc_return        | 1         |

