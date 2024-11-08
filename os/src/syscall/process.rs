//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    config::{
        MAX_SYSCALL_NUM,
        PAGE_SIZE
    },
    loader::get_app_data_by_name,
    mm::{
        translated_refmut, translated_str, translated_byte_buffer, MapPermission, VirtAddr,
    },
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus, TaskControlBlock
    },
    timer::{get_time_us, get_time_ms},
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
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
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
    trace!("kernel:pid[{}] sys_task_info", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let inner = current_task.inner_exclusive_access();
    let task_info = TaskInfo {
        status: inner.get_status(),
        syscall_times: inner.syscall_times,
        time: get_time_ms() - inner.starting_time,
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
    let current_task = current_task().unwrap();
    let memory_set = &mut current_task.inner_exclusive_access().memory_set;
    let start_addr: VirtAddr = start.into();
    let end_addr: VirtAddr = (start + len).into();
    let port = Port::from_bits(port).unwrap();
    memory_set.mmap(start_addr, end_addr, port.into())
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    let current_task = current_task().unwrap();
    let memory_set = &mut current_task.inner_exclusive_access().memory_set;
    let start_addr: VirtAddr = start.into();
    let end_addr: VirtAddr = (start + len).into();
    memory_set.munmap(start_addr, end_addr)
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn",
        current_task().unwrap().pid.0
    );
    let task_name = translated_str(current_user_token(), path);
    let Some(task_data) = get_app_data_by_name(task_name.as_str()) else {
        return -1;
    };
    let task = Arc::new(TaskControlBlock::new(&task_data));
    current_task().unwrap().inner_exclusive_access().children.push(task.clone());
    add_task(task.clone());
    let pid = task.getpid();
    pid as isize
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );
    if prio <= 1 {
        return -1;
    }
    let current_task = current_task().unwrap();
    current_task.inner_exclusive_access().priority = prio;
    prio
}
