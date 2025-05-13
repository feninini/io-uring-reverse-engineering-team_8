# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice. 

### alloc_cache.c
Implements a memory object cache for io_uring, designed to optimize object allocation and deallocation. It provides functions to initialize the cache io_alloc_cache_init, allocate new objects from the cache io_cache_alloc_new, and free all cached entries io_alloc_cache_free. The cache reduces memory allocation overhead by reusing objects, improving performance in scenarios with frequent memory operations.

### cancel.c
Manage cancellation of I/O requests in io\_uring, processing asynchronous and synchronous cancellations. It evaluates flags such as file descriptors or operation types to match and cancel requests, utilizing worker queues and locks to handle cancellations safely and efficiently.

### epoll.c
Connects epoll_ctl and epoll_wait with io_uring, enabling non-blocking event management and error handling, such as -EAGAIN.

### eventfd.c
Integrates eventfd with io\_uring for managing event notifications in a thread-safe way, utilizing RCU and reference counting. Supports registering, unregistering, and triggering events via eventfd, while synchronizing with io\_uring’s completion queue, including asynchronous operations.

### fdinfo.c
Shows io\_uring's internal status in /proc, including data on submission and completion queues, user buffers, and related files. It also reports on NAPI support, cancelable I/O operations, and overflow entries, offering insight for debugging and monitoring the io\_uring context.

### filetable.c
Handles file descriptors within the io_uring framework in Linux, focusing on allocating, installing, and removing file descriptors. It uses a bitmap to track available slots in the file table and includes functions to allocate and free memory for these tables. The io_install_fixed_file and __io_fixed_fd_install functions assign file descriptors to specific slots, while also managing errors. The io_fixed_fd_remove function removes file descriptors, and io_register_file_alloc_range validates allocation ranges. Overall, it provides efficient file descriptor management for io_uring.

### fs.c
Handles asynchronous filesystem operations (rename, unlink, mkdir, symlink, and link) in the io_uring framework. Each operation prepares the necessary data, performs the task, and cleans up allocated memory. The functions ensure non-blocking execution by handling filesystem tasks asynchronously without affecting other processes.

### futex.c
Combines futex operations with io_uring to manage asynchronous futex wait and wake actions. It sets up structures to handle futex-related data, processes and completes requests, and manages errors and cancellations. The implementation supports both individual and multiple futexes, utilizing a futex data cache for better memory management, which enhances performance in multi-threaded contexts.

### io-wq.c
Manages a thread pool for io_uring, handling creation, execution, and cleanup of worker threads. It assigns tasks from a queue, tracks worker states, and ensures efficient asynchronous I/O processing with support for stalled or dependent work.

### io_uring.c

### kbuf.c
Manages buffer groups in Linux's io_uring, allowing applications to pre-register and reuse memory buffers for fast asynchronous I/O. It supports both legacy and ring-based buffer management, handling selection, recycling, and synchronization to optimize performance and reduce memory overhead.

### memmap.c
Handles memory regions used by io_uring in the Linux kernel, including allocation, mapping, and pinning of memory from either user space or the kernel. It ensures secure and efficient access through mmap, supports systems with or without an MMU, and performs various safety checks to maintain correctness.

### msg_ring.c
Provides the implementation for IORING_OP_MSG_RING in the Linux io_uring subsystem, allowing one io_uring context (or ring) to send messages—either data or file descriptors—to another ring. It defines how messages are structured and manages their delivery, handling synchronization between source and target rings through locking and task work mechanisms. The code supports two message types: IORING_MSG_DATA for sending user-defined data that appears as a completion in the target ring, and IORING_MSG_SEND_FD for transferring a file descriptor into the target's fixed file table. It ensures proper resource allocation, reference management, and cleanup during cross-ring communication.

### napi.c
Integrates NAPI (New API) busy-polling with Linux io_uring to optimize low-latency network receive operations. It manages a hash table of NAPI IDs per io_uring context, allowing registration, deregistration, and cleanup of entries. It enables efficient busy-polling loops, reducing network IO latency, and uses synchronization mechanisms like spinlocks and RCU to ensure thread-safe access to shared data structures.

### net.c
Provides the implementation of asynchronous network socket operations for Linux io_uring, including support for sending, receiving, connecting, binding, listening, and shutting down sockets. It defines data structures and helper functions to manage the preparation, execution, and cleanup of these operations, handling both regular and compatibility (32-bit) user-space message headers. The code manages I/O vectors, buffer selection, and message copying between user and kernel space, while supporting optimizations such as buffer caching and multishot (batched) receives. It ensures correct resource management and error handling for efficient, low-latency network I/O within the io_uring framework, leveraging Linux kernel abstractions for safe and performant asynchronous socket communication.

### nop.c
Implements the IORING_OP_NOP operation in the io_uring subsystem of the Linux kernel. The nop operation is a no-op (no operation) that is used to perform minimal work, such as injecting a result or dealing with file descriptors or buffers in specific ways. The code allows for setting flags to inject specific results (like setting a custom return value), work with fixed files or buffers, and manage file descriptors within the io_uring request. It also defines the io_nop_prep function to set up the request, parsing the necessary flags and values, and the io_nop function to execute the no-op logic, including handling file and buffer retrieval, and setting the result accordingly.

### notif.c
Managing zero-copy buffers for notifications. It includes functions to allocate a notification structure io_kiocb, handle the completion of buffer transmissions io_tx_ubuf_complete, and link socket buffers io_link_skb. It ensures proper buffer handling and reference counting for zero-copy operations, with operations defined in io_ubuf_ops.

### opdef.c
Defines a table of operations for handling different types of I/O requests in the io\_uring subsystem of the Linux kernel. Each entry in the io_issue_defs array corresponds to a specific I/O operation (e.g., reading, writing, polling, etc.) and contains function pointers to the preparation prep and issue issue functions that define how each operation is processed. The operations are structured to handle both file and network operations, as well as advanced I/O features like async cancellation, timeouts, and polling. Some operations also include additional flags for managing behavior (e.g., audit_skip, iopoll, pollin, etc.) and determine whether the operation requires a file descriptor or can handle non-regular files. The modular approach enables extensibility and efficient handling of different types of I/O requests.

### openclose.c
Manages file operations within the io_uring subsystem of the Linux kernel, focusing on opening and closing files asynchronously. It defines structures and functions for preparing and executing file open io_openat and io_openat2 and close io_close operations using io_uring's enhanced I/O model. The io_openat functions support file opening with flags like O_CREAT and O_TMPFILE, managing file descriptors, and handling asynchronous requests. For file closing, the io_close functions ensure proper cleanup of file descriptors, including handling non-blocking operations and flushing requirements. Additionally, it provides support for fixed file descriptors, ensuring they are correctly installed or removed. The functions make extensive use of flags and error handling to ensure efficient and safe file operations within the I/O ring context.

### poll.c
Handles polling for I/O events in **io\_uring**, a high-performance I/O API in Linux. It manages file descriptor events like readiness for read/write, using atomic operations and synchronization to efficiently detect events, handle retries, and cancel or remove poll requests. The goal is to enable fast, asynchronous I/O operations with minimal overhead.

### register.c
Manages resources like submission and completion queues, and buffers used for I/O operations. The code initializes, resizes, and registers these queues, while handling memory management for buffers. By setting thread affinity for queues, it optimizes I/O performance across multiple CPUs. It leverages io_uring's event-driven model to minimize context-switching, reduce latency, and improve throughput in large-scale I/O tasks, such as file operations or networking, without blocking the application.

### rsrc.c
Handling the registration, validation, and updating of file descriptors, buffers, and memory resources used by io_uring for efficient I/O operations. The functions deal with registering and managing resources (like files and buffers) within a ring, including handling memory accounting (for pinned memory), checking buffer validity, and ensuring resources are properly released when no longer needed. The code also includes logic for handling errors like invalid file descriptors or memory overflows, and efficiently managing resource allocation, deallocation, and updates to support scalable and high-performance I/O operations in Linux.

### rw.c
Manages asynchronous I/O operations in io_uring for efficient read/write handling. It prepares and executes I/O requests, including direct and vectored I/O, while managing buffers, priorities, and completion states. It also optimizes memory usage and error handling for better performance in high-throughput scenarios.

### splice.c
Handling the splice mechanism, which efficiently transfers data between file descriptors without copying data into user space. It prepares and manages the state for both io_splice and io_tee operations. The functions handle different aspects like validating splice flags, preparing file descriptors, reading and writing data through do_splice() or do_tee(), and cleaning up resources afterward. It utilizes io_uring's infrastructure to efficiently handle these I/O tasks asynchronously, ensuring that resource management and error handling are properly done during the operations.

### sqpoll.c
Manages the submission queue (SQ) polling in the Linux kernel’s io\_uring subsystem, where it offloads the task of polling the SQ from the application to a dedicated kernel thread. This approach improves performance by allowing the kernel to manage the polling and execution of submitted I/O operations asynchronously, reducing the overhead of system calls. It involves several key functions: creating and managing a kernel thread io_sq_thread to poll and process submission queue events, managing CPU affinity for the polling thread, handling thread parking and un-parking, processing task work (like retries), and coordinating with multiple **io\_ring\_ctx** (ring context) structures. The code ensures that I/O operations are handled efficiently by controlling thread scheduling, synchronization, and resource management.

### statx.c
Implements asynchronous statx operations using io\_uring. It prepares the request by extracting file and operation parameters, executes the statx*system call to retrieve extended file metadata, and stores the result. Cleanup is performed by freeing the filename memory used during the operation. This allows efficient, non-blocking file status retrieval.

### sync.c
It includes functions to prepare and perform system calls such as sync_file_range, fsync, and fallocate. The preparation functions check the validity of input parameters (e.g., offset, length, and flags) from the submission queue entries (SQEs) and set flags for asynchronous execution. The core functions io_sync_file_range, io_fsync, io_fallocate execute the synchronization and allocation tasks, ensuring that these actions are blocking when needed, and trigger file system modification notifications while updating the operation results in the request structure.

### tctx.c
Handles managing task contexts and worker queues in the io\_uring subsystem of the Linux kernel. It allows tasks to register and unregister file descriptors for efficient asynchronous I/O, ensuring proper resource allocation and cleanup. The functions manage task-specific data, such as associating tasks with io\_uring queues, and optimize I/O operations by minimizing redundant file descriptor lookups.

### timeout.c
Manages timeouts for asynchronous I/O operations in the Linux kernel's I/O uring subsystem. It handles setting, updating, and canceling timeout events, using high-resolution timers hrtimer for precise timing. It ensures synchronization, processes timeouts for both single and repeated operations, and updates the status of related requests in the I/O completion queue.

### truncate.c
Implements asynchronous file truncation using io\_uring. io_ftruncate_prep validates the truncation request, extracts the truncation length, and ensures asynchronous execution. io_ftruncate performs the truncation by calling do_ftruncate, then sets and returns the result of the operation. This allows non-blocking file truncation for improved I/O performance.

### uring_cmd.c
Integrates socket operations with the io\_uring framework for efficient asynchronous I/O. It handles command preparation, cancellation, and cleanup, manages memory via caching, and supports socket operations like getsockopt and setsockopt in a non-blocking context, optimizing performance in socket-based I/O tasks.

### waitid.c
Adds async support for waitid() in io_uring, allowing processes to wait for child process state changes. It manages request submission, cancellation, and completion using references, locks, and waitqueues to ensure synchronization, handle errors, and avoid race conditions.

### xattr.c
Enables asynchronous handling of extended file attributes (xattr) operations via io\_uring, allowing efficient get and set operations on file attributes. It handles both file-based and pathname-based xattr operations, managing context, memory, and errors. The code uses io\_uring's async mechanisms to ensure efficient execution, with proper cleanup and memory management for each operation.

### zcrx.c
Handles zero-copy network I/O using io_uring for efficient asynchronous data transfer. It manages memory buffers and network device queues, optimizing data handling by directly mapping memory for DMA operations. The functions allocate, free, and synchronize memory regions, ensuring low CPU usage and high throughput for networked applications by enabling zero-copy operations between the device and memory.

## another source

## Headers
### advice.h
Just declare the function specification. 
