## Why use Async

Ptrace as it is designed, is event-based. Some logics, like the handling of a clone() syscall
can be so complicated and involve waiting for a specific sequence of events, in a generic event
loop.

This is perfect for single-threaded async logics like the JavaScript's Promise callbacks. 

Rust provides a zero-cost compilation of async functions into synchronous state machines.
Why not make use of it, in a single-threaded fashion, through our own lightweight runtime?

### Spaghetti Ptrace logics

One benefit this provides is that Rust will automatically compile meaningful, human-readable
async logics into the synchronous Spaghetti state machine that the kernel expects from ptrace 

Consider the flow of handling a clone() system call.

* There is the initial `PTRACE_SYSCALL` event that marks the beginning of clone
* There is the interception of SIGCHLD to detect the child's PID
* There is the interception of a special `PTRACE_EVENT` event to handle clone-specific updates


In a normal event loop, the logics for all three will be scattered like so

```
```

Side Note:

> Fundamentally, the code is scattered because tracee can encounter other surprises during this
> time, and simply crash or receives a signal, etc. So the synchronous event loop cannot simply
> **block** all handling of other events to simply serve clone() only
>
> You could say that we can make an exception for clone(). But then there are plenty of other
> system calls that require specific chain of events admist a chaos of other possible outcomes.
>
> Why make an exception when there is a clean pattern to rely on? Especially when we know
> there will simply be more and more "exceptions" to make? That's how Spaghetti code starts.

In an async event loop, the logics will look much simpler:


We can gather all these steps in one place, and then simply wait for a "ptrace future" that
unblocks us whenever the correct next stage happens

### RwLocks

Another benefit this provides, is to reduce overhead from RwLocks

Ptrace is oddly a very good example of an async event loop that is always wrongly
implemented as a synchronos tracer... Consider the typical Rust code needed to
track the current pointer location of a stack

```
pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    pub pid: Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    // ...

    pub tracee_stack_offset: RwLock<usize>,

    // ...
}

```

```
    // Send the content of `bytes` to tracee's stack, and return its address.
    // This can be called multiple times and will add new content to the end of
    // previous contents.
    pub fn tracee_stack_append(&self, bytes: Vec<u8>) -> Result<usize, SysAugError> {
        let pid = self.pid;
        let mut offset = rwlock_write(&self.tracee_stack_offset)?;
        let old_offset = *offset;
        let (addr, new_offset) = self.ptrace_client.execute(move || {
            let final_bytes = bytes.as_slice();
            unsafe { ptrace::write_bytes_to_tracee(pid, old_offset, final_bytes) }
        })??;
        *offset = new_offset;
        Ok(addr)
    }

    pub fn tracee_stack_append_path(&self, path: PathBuf) -> Result<usize, SysAugError> {
        let bytes = path.into_os_string().into_vec();
        self.tracee_stack_append(bytes)
    }

    // Change the address, to which the next tracee_stack_append will write contents.
    // offset = how many bytes of previously written contents will stay after this
    pub fn tracee_stack_seek(&self, offset: usize) -> Result<(), SysAugError> {
        let mut ref_offset = rwlock_write(&self.tracee_stack_offset)?;
        *ref_offset = offset;
        Ok(())
    }
```

Whenever synchronous logic is involved, we introduce a global state and must have a RwLock.

One way to avoid the RwLock is to use a second single-threaded Struct. But that won't resolve
other issues with writing asynchronous callback handlers by hand.


## Implementing our own Lightweight Async Runtime

Note: The implementation would work MUCH better if we can do tokio runtime one turn at a
time (pausing at each await) instead of block_on 
    And, this would also need a special PendingOrReady struct that can change between
    the two states while being awaited on (without "replacing" the future?)

ALTERNATIVELY, maybe implement our own future that wraps ALL ptrace actions
    |
    .--> THIS IS BETTER!

    Need to have our own struct PtraceFuture impl Future

    IF tokio doesn't support turn-by-turn execeution, then we also need to write 
    our own Async runtime, which essentially just runs one
    "turn"/poll each time, returning the PtraceFuture that caused the await.

    And this PtraceFuture will describe to the ptrace crate what we are waiting FOR.

    Why?

    This will allow us to write async code in the most semantic way.

    await tracee_init_mmap()
    while (syscall = syscall_status_generator.next().await) {
      await syscall_augtable[syscall.num]();
    }

    And the turn-by-turn execution make sure we restart from the last "yield"
