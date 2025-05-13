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

