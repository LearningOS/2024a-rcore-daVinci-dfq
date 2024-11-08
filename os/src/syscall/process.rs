//! Process management syscalls
use crate::{
    config::{
        MAX_SYSCALL_NUM,
        PAGE_SIZE
    },
    task::{
        change_program_brk, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus, get_starting_time, get_syscall_times, mmap, munmap
    },
    timer::{get_time_us, get_time_ms},
    mm::{
        translated_byte_buffer,
        MapPermission,
        VirtAddr,
    },
    task::current_user_token,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let time_val_len = core::mem::size_of::<TimeVal>();
    let mut buffers = translated_byte_buffer(current_user_token(), ts as *const u8, time_val_len);
    let mut bytes_copied = 0;
    let time_val_bytes = unsafe {
        core::slice::from_raw_parts(
            &time_val as *const TimeVal as *const u8,
            time_val_len
        )
    };
    for buffer in &mut buffers {
        let buffer_len = buffer.len();
        if buffer_len + bytes_copied >= time_val_len {
            let end = time_val_len - bytes_copied;
            buffer[..end].copy_from_slice(
                &time_val_bytes[bytes_copied..time_val_len]
            );
            bytes_copied += end;
            break;
        } else {
            buffer.copy_from_slice(
                &time_val_bytes[bytes_copied..bytes_copied + buffer_len]
            );
            bytes_copied += buffer_len
        }
    }
    if bytes_copied != time_val_len {
        return -1;
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    let task_info = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: get_syscall_times(),
        time: get_time_ms() - get_starting_time(),
    };
    let task_info_len = core::mem::size_of::<TaskInfo>();
    let mut buffers = translated_byte_buffer(current_user_token(), ti as *const u8, task_info_len);
    let mut bytes_copied = 0;
    let task_info_bytes = unsafe {
        core::slice::from_raw_parts(
            &task_info as *const TaskInfo as *const u8,
            task_info_len
        )
    };
    for buffer in &mut buffers {
        let buffer_len = buffer.len();
        if buffer_len + bytes_copied >= task_info_len {
            let end = task_info_len - bytes_copied;
            buffer[..end].copy_from_slice(
                &task_info_bytes[bytes_copied..task_info_len]
            );
            bytes_copied += end;
            break;
        } else {
            buffer.copy_from_slice(
                &task_info_bytes[bytes_copied..bytes_copied + buffer_len]
            );
            bytes_copied += buffer_len;
        }
    }
    if bytes_copied != task_info_len {
        return -1;
    }
    0
}

bitflags! {
    pub struct Port: usize {
        ///Readable
        const R = 1 << 0;
        ///Writable
        const W = 1 << 1;
        ///Excutable
        const X = 1 << 2;
    }
}

impl From<Port> for MapPermission {
    fn from(port: Port) -> Self {
        let mut map_perm = MapPermission::empty();
        if port.contains(Port::R) {
            map_perm |= MapPermission::R;
        }
        if port.contains(Port::W) {
            map_perm |= MapPermission::W;
        }
        if port.contains(Port::X) {
            map_perm |= MapPermission::X;
        }
        map_perm
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if (port & !0x7 != 0) || (port & 0x7 == 0) {
        return -1;
    }
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    let start_addr: VirtAddr = start.into();
    let end_addr: VirtAddr = (start + len).into();
    let port = Port::from_bits(port).unwrap();
    mmap(start_addr, end_addr, port.into())
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    let start_addr: VirtAddr = start.into();
    let end_addr: VirtAddr = (start + len).into();
    munmap(start_addr, end_addr)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
