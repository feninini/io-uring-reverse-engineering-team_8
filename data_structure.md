# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter

If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.

### memmap,c
Structure name       | Defined in         | Attributes                                                                                      | Caller Functions Source                | source caller          | usage
---------------------|--------------------|--------------------------------------------------------------------------------------------------|----------------------------------------|------------------------|--------------------------
page                 | io_uring/memmap.c  | (struct) page                                                                                   | io_mem_alloc_compound                  | io_uring/memmap.c      | local variable
                     |                    |                                                                                                  | io_pin_pages                           | io_uring/memmap.c      | local variable
                     |                    |                                                                                                  | io_region_init_ptr                     | io_uring/memmap.c      | dereferenced through pages
page **              | io_uring/memmap.c  | array of pointers to struct page                                                                 | io_mem_alloc_compound                  | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_pin_pages                           | io_uring/memmap.c      | return value
                     |                    |                                                                                                  | io_region_pin_pages                    | io_uring/memmap.c      | local variable
                     |                    |                                                                                                  | io_region_allocate_pages               | io_uring/memmap.c      | local variable, assigned to mr->pages
                     |                    |                                                                                                  | io_free_region                         | io_uring/memmap.c      | freed and accessed via mr
io_mapped_region     | io_uring/memmap.c  | pages, ptr, nr_pages, flags                                                                      | io_region_init_ptr                     | io_uring/memmap.c      | parameter, dereferenced
                     |                    |                                                                                                  | io_region_pin_pages                    | io_uring/memmap.c      | parameter, assigned
                     |                    |                                                                                                  | io_region_allocate_pages               | io_uring/memmap.c      | parameter, assigned
                     |                    |                                                                                                  | io_create_region                       | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_create_region_mmap_safe             | io_uring/memmap.c      | parameter, local copy made
                     |                    |                                                                                                  | io_free_region                         | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_mmap_get_region                     | io_uring/memmap.c      | return value
io_ring_ctx          | linux/io_uring_types.h | ring_region, sq_region, mmap_lock, user, param_region, zcrx_region                            | io_region_pin_pages                    | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_region_allocate_pages               | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_create_region                       | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_create_region_mmap_safe             | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_mmap_get_region                     | io_uring/memmap.c      | parameter
io_uring_region_desc | linux/io_uring_types.h | user_addr, size, flags, mmap_offset, id, __resv                                                 | io_region_pin_pages                    | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_region_allocate_pages               | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_create_region                       | io_uring/memmap.c      | parameter
                     |                    |                                                                                                  | io_create_region_mmap_safe             | io_uring/memmap.c      | parameter
io_imu_folio_data    | io_uring/kbuf.h    | nr_folios                                                                                        | io_region_init_ptr                     | io_uring/memmap.c      | local variable

