//! init — the first user-space process.
//!
//! Deliberately small, and not a service manager yet. Its job is to be the
//! proof that ring 3 exists and that the scheduler is real: that the kernel can
//! build a user address space, enter it, service a system call, take the
//! processor away mid-loop, and give it back with every register intact.
//!
//! Two instances of this same image run at once, in separate address spaces,
//! distinguished only by the value the kernel puts in `rdi`. Neither can
//! observe the other; the interleaving in the boot log is the only evidence
//! either was ever descheduled.
//!
//! The refusal checks matter most. Printing from ring 3 shows the path works;
//! being *refused* shows the boundary is real. A kernel that happily read a
//! kernel pointer on behalf of a user process would pass every other check
//! here.

#![no_std]
#![no_main]

/// The syscall numbers and calling convention, compiled from the same file the
/// kernel compiles.
#[path = "../../../kernel/spectre-kernel/src/abi.rs"]
mod abi;

use abi::{
    decode, SyscallError, MAX_LOG_BYTES, PING_COOKIE, SYS_CALL, SYS_DEVICE_INFO, SYS_EXIT, SYS_LOG,
    SYS_MAP_DEVICE, SYS_PING, SYS_RECEIVE, SYS_REPLY,
};

/// An address inside the kernel's identity map. User space must never be able
/// to make the kernel read it on its behalf.
const KERNEL_ADDRESS: u64 = 0x0200_0000;

/// A syscall number nothing implements.
const UNASSIGNED_SYSCALL: u64 = 9999;

/// Rounds of the work loop.
///
/// Enough that a 10 ms timer slice cannot cover them all, so at least one
/// preemption has to happen somewhere in the middle. Few enough that the boot
/// test does not spend a noticeable time on it.
const ROUNDS: u64 = 6;

/// Iterations of the busy loop per round, chosen to take a few milliseconds.
const SPIN: u64 = 3_000_000;

fn log(message: &str) {
    // SAFETY: the pointer and length describe a live `&str` in this process's
    // own image, which is exactly what the kernel will validate.
    unsafe {
        abi::syscall2(SYS_LOG, message.as_ptr() as u64, message.len() as u64);
    }
}

fn log_bytes(bytes: &[u8]) {
    // SAFETY: `bytes` is a live local slice and the length is its exact size.
    unsafe {
        abi::syscall2(SYS_LOG, bytes.as_ptr() as u64, bytes.len() as u64);
    }
}

/// Writes `value` as hex into `out`, returning the written slice.
///
/// By hand because there is no allocator and no reason to pull `core::fmt` into
/// a process this small.
fn hex(value: u64, out: &mut [u8; 18]) -> &[u8] {
    out[0] = b'0';
    out[1] = b'x';
    for nibble in 0..16 {
        let digit = ((value >> (60 - nibble * 4)) & 0xF) as u8;
        out[2 + nibble] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
    }
    &out[..]
}

/// `[init N] ` prefix, so two processes are distinguishable in one log.
fn tag(pid: u64, out: &mut [u8; 10]) -> &[u8] {
    let text = b"[init ?] ";
    out[..text.len()].copy_from_slice(text);
    out[6] = b'0' + (pid % 10) as u8;
    &out[..text.len()]
}

/// Emits one tagged line in a single system call.
///
/// Building the line first is not tidiness. A process can be preempted between
/// two calls, so writing a prefix and then a message as separate calls lets
/// another process interleave inside the line — which it did, and the result
/// was output that read as though the kernel had scrambled it. One call per
/// line is the only way to make a line atomic without a lock user space does
/// not have.
fn say(pid: u64, parts: &[&[u8]]) {
    let mut line = [0u8; 192];
    let mut len = 0usize;

    let mut prefix = [0u8; 10];
    for chunk in core::iter::once(tag(pid, &mut prefix) as &[u8]).chain(parts.iter().copied()) {
        let take = chunk.len().min(line.len() - len - 1);
        line[len..len + take].copy_from_slice(&chunk[..take]);
        len += take;
    }
    line[len] = b'\n';
    len += 1;
    log_bytes(&line[..len]);
}

/// Clients the server answers before it stops. Two of the three processes are
/// clients; the third owns the endpoint.
const CLIENTS: usize = 2;

fn call5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> Result<u64, SyscallError> {
    // SAFETY: every call site passes arguments the corresponding syscall
    // accepts, or deliberately does not — the refusals are the point.
    decode(unsafe { abi::syscall5(number, a0, a1, a2, a3, a4) })
}

fn call(number: u64, a0: u64, a1: u64) -> Result<u64, SyscallError> {
    // SAFETY: every call site below passes arguments the corresponding syscall
    // accepts, or deliberately does not — the refusals are the point.
    decode(unsafe { abi::syscall2(number, a0, a1) })
}

fn expect_refused(pid: u64, what: &str, expected: SyscallError, result: Result<u64, SyscallError>) {
    match result {
        Err(error) if error == expected => {
            say(pid, &[b"refused as expected: ", what.as_bytes()]);
        }
        _ => {
            say(pid, &[b"SECURITY CHECK FAILED: ", what.as_bytes()]);
            exit(2);
        }
    }
}

fn exit(code: u64) -> ! {
    // SAFETY: `SYS_EXIT` does not return.
    unsafe {
        abi::syscall1(SYS_EXIT, code);
    }
    // The kernel does not come back from `SYS_EXIT`, but the compiler cannot
    // know that, and falling off the end of a `-> !` function would execute
    // whatever follows.
    loop {
        core::hint::spin_loop();
    }
}

/// Burns time without calling the kernel.
///
/// The point is to be interruptible and nothing else. `black_box` keeps the
/// optimiser from noticing the loop has no effect and deleting it, which would
/// remove the only window in which a timer tick can land.
fn spin(iterations: u64) {
    let mut sink = 0u64;
    for i in 0..iterations {
        sink = core::hint::black_box(sink.wrapping_add(i));
    }
    core::hint::black_box(sink);
}

#[no_mangle]
pub extern "sysv64" fn _start(pid: u64, endpoint: u64, grant: u64) -> ! {
    say(pid, &[b"hello from ring 3"]);

    // The round trip. Printing could be faked by a kernel that never left ring
    // 0; a value the kernel transformed and returned could not.
    let sent = 0x0123_4567_89AB_CDEF ^ pid;
    match call(SYS_PING, sent, 0) {
        Ok(reply) if reply == sent ^ PING_COOKIE => {
            let mut buffer = [0u8; 18];
            say(
                pid,
                &[b"ping round trip ok, reply ", hex(reply, &mut buffer)],
            );
        }
        _ => {
            say(pid, &[b"PING FAILED"]);
            exit(1);
        }
    }

    // --- the boundary ----------------------------------------------------
    // Each of these would be a privilege escalation if it succeeded.

    expect_refused(
        pid,
        "reading kernel memory through SYS_LOG",
        SyscallError::BadPointer,
        call(SYS_LOG, KERNEL_ADDRESS, 16),
    );
    expect_refused(
        pid,
        "a length past the end of the buffer limit",
        SyscallError::TooLong,
        call(SYS_LOG, 0x1000_0000_0000, MAX_LOG_BYTES as u64 + 1),
    );
    expect_refused(
        pid,
        "an unassigned syscall number",
        SyscallError::BadNumber,
        call(UNASSIGNED_SYSCALL, 0, 0),
    );

    // --- the scheduler ----------------------------------------------------
    // A loop that never enters the kernel. Anything that happens between two
    // rounds happened because the processor was taken away, not because this
    // process asked for anything.
    for round in 0..ROUNDS {
        spin(SPIN);
        let digit = [b'0' + (round % 10) as u8];
        say(pid, &[b"round ", &digit]);
    }

    // --- driving a device -------------------------------------------------
    // Only the process the kernel gave a grant to gets past the first call.
    // Everything else here holds zero, and zero never matches.
    drive_display(pid, grant);

    // --- talking to another process ---------------------------------------
    if endpoint != 0 {
        if pid == SERVER_ROLE {
            serve(pid, endpoint);
        } else {
            request(pid, endpoint);
        }
    }

    say(pid, &[b"all checks passed"]);
    exit(0);
}

/// The process that owns the endpoint. Given the endpoint by the kernel at
/// spawn; every other process is a client.
const SERVER_ROLE: u64 = 1;

/// What `SYS_DEVICE_INFO` writes. The layout is the kernel's `DeviceInfo`, and
/// like the syscall numbers it is one definition compiled by both sides — this
/// copy exists because the kernel's is behind a module user space does not
/// include, and the `assert` below is what keeps them the same size.
#[derive(Clone, Copy)]
#[repr(C)]
struct DeviceInfo {
    kind: u32,
    _pad: u32,
    length: u64,
    width: u32,
    height: u32,
    stride: u32,
    bytes_per_pixel: u32,
}

const _: () = assert!(core::mem::size_of::<DeviceInfo>() == 32);

/// `DeviceKind::Framebuffer`.
const DEVICE_FRAMEBUFFER: u32 = 1;

/// Maps the framebuffer and draws on it, from ring 3.
///
/// This is the first time anything outside the kernel touches hardware. The
/// process never names a physical address: it asks for device zero, and the
/// kernel — which is the only thing that knows where device zero is — maps it.
fn drive_display(pid: u64, grant: u64) {
    let mut info = DeviceInfo {
        kind: 0,
        _pad: 0,
        length: 0,
        width: 0,
        height: 0,
        stride: 0,
        bytes_per_pixel: 0,
    };
    let size = core::mem::size_of::<DeviceInfo>() as u64;

    match call5(SYS_DEVICE_INFO, grant, 0, (&raw mut info) as u64, size, 0) {
        Ok(_) => {}
        Err(SyscallError::NotPermitted) => {
            // The expected answer for every process that is not the driver.
            say(pid, &[b"no device grant, as expected"]);
            return;
        }
        Err(error) => {
            say(pid, &[b"device info failed: ", error.name().as_bytes()]);
            exit(9);
        }
    }

    if info.kind != DEVICE_FRAMEBUFFER || info.bytes_per_pixel != 4 {
        say(pid, &[b"device 0 is not a framebuffer this driver knows"]);
        return;
    }

    let base = match call5(SYS_MAP_DEVICE, grant, 0, 0, 0, 0) {
        Ok(base) => base,
        Err(error) => {
            say(pid, &[b"map failed: ", error.name().as_bytes()]);
            exit(10);
        }
    };

    let mut digits = [0u8; 18];
    say(
        pid,
        &[
            b"framebuffer mapped from ring 3 at ",
            hex(base, &mut digits),
        ],
    );

    draw_banner(base, &info);
    say(
        pid,
        &[b"drew to the framebuffer without entering the kernel"],
    );
}

/// Paints a band across the bottom of the screen.
///
/// Deliberately somewhere the kernel's own console does not write, so what
/// appears is unambiguously the work of a user-space process rather than a
/// kernel line that happened to scroll past.
fn draw_banner(base: u64, info: &DeviceInfo) {
    let height = info.height as usize;
    let width = info.width as usize;
    let stride = info.stride as usize;
    let band_height = 96usize;
    if height < band_height + 8 || width == 0 {
        return;
    }
    let top = height - band_height;

    for y in 0..band_height {
        // A vertical gradient, so a band that is drawn but wrong is still
        // obviously drawn.
        let level = (y * 255 / band_height) as u32;
        let colour = (level / 5) << 16 | (level / 2) << 8 | (0x40 + level / 2);
        for x in 0..width {
            // SAFETY: the mapping covers `stride * height` pixels and both
            // indices are inside it. The kernel mapped this range for this
            // process; nothing else in the address space overlaps it.
            unsafe {
                let pixel = (base as *mut u32).add((top + y) * stride + x);
                pixel.write_volatile(colour);
            }
        }
    }

    let text = b"USER SPACE DREW THIS";
    draw_text(base, stride, 24, top + 36, text, 0x00FF_FFFF);
}

/// The same 5x7 shapes the kernel console uses, at three times the size.
///
/// A copy of the outline rather than the table: a user-space process has no
/// business including a kernel module, and this draws twenty characters once.
fn draw_text(base: u64, stride: usize, x0: usize, y0: usize, text: &[u8], colour: u32) {
    const SCALE: usize = 3;
    for (index, &byte) in text.iter().enumerate() {
        let rows = kernel_glyph(byte);
        for (row, bits) in rows.iter().copied().enumerate() {
            for column in 0..5usize {
                if bits & (1 << (4 - column)) == 0 {
                    continue;
                }
                for sy in 0..SCALE {
                    for sx in 0..SCALE {
                        let x = x0 + index * 6 * SCALE + column * SCALE + sx;
                        let y = y0 + row * SCALE + sy;
                        // SAFETY: inside the mapped framebuffer; the caller
                        // bounded `y0` against the band it just filled.
                        unsafe {
                            (base as *mut u32)
                                .add(y * stride + x)
                                .write_volatile(colour);
                        }
                    }
                }
            }
        }
    }
}

/// Just the letters this banner needs.
const fn kernel_glyph(c: u8) -> [u8; 7] {
    match c {
        b'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'C' => [0x0f, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0f],
        b'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        b'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        b'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'I' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f],
        b'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        b' ' => [0; 7],
        _ => [0x1f, 0x11, 0x02, 0x04, 0x08, 0x00, 0x08],
    }
}

/// Requests the server answers. Chosen so the reply is a transformation the
/// client can check rather than an echo, which a kernel that lost the message
/// could also produce.
const REQUEST: &[u8] = b"WHISEZ-PING";
const EXPECTED_REPLY: &[u8] = b"WHISEZ-PONG";

/// Answers one request per client, then stops.
fn serve(pid: u64, endpoint: u64) -> ! {
    let mut buffer = [0u8; 64];

    for _ in 0..CLIENTS {
        let len = match call5(
            SYS_RECEIVE,
            endpoint,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            0,
            0,
        ) {
            Ok(len) => len as usize,
            Err(error) => {
                say(pid, &[b"receive failed: ", error.name().as_bytes()]);
                exit(4);
            }
        };

        say(pid, &[b"served request: ", &buffer[..len]]);

        // The transformation the client checks for. A server that replied with
        // the request unchanged would be indistinguishable from a kernel that
        // handed the buffer straight back.
        let mut answer = [0u8; 64];
        answer[..len].copy_from_slice(&buffer[..len]);
        if len == REQUEST.len() {
            answer[..len].copy_from_slice(EXPECTED_REPLY);
        }

        if let Err(error) = call5(
            SYS_REPLY,
            endpoint,
            answer.as_ptr() as u64,
            len as u64,
            0,
            0,
        ) {
            say(pid, &[b"reply failed: ", error.name().as_bytes()]);
            exit(5);
        }
    }

    say(pid, &[b"served every client"]);
    say(pid, &[b"all checks passed"]);
    exit(0)
}

/// Sends one request and checks the answer.
fn request(pid: u64, endpoint: u64) {
    let mut reply = [0u8; 64];

    let len = match call5(
        SYS_CALL,
        endpoint,
        REQUEST.as_ptr() as u64,
        REQUEST.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    ) {
        Ok(len) => len as usize,
        Err(error) => {
            say(pid, &[b"call failed: ", error.name().as_bytes()]);
            exit(6);
        }
    };

    if &reply[..len] == EXPECTED_REPLY {
        say(
            pid,
            &[b"ipc round trip ok, server answered ", &reply[..len]],
        );
    } else {
        say(pid, &[b"IPC REPLY WRONG"]);
        exit(7);
    }

    // An endpoint this process does not own must refuse to be received from,
    // however it was obtained.
    match call5(SYS_RECEIVE, endpoint, reply.as_mut_ptr() as u64, 8, 0, 0) {
        Err(SyscallError::BadEndpoint) => {
            say(
                pid,
                &[b"refused as expected: receiving on an endpoint it does not own"],
            );
        }
        _ => {
            say(
                pid,
                &[b"SECURITY CHECK FAILED: received on another endpoint"],
            );
            exit(8);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    log("[init] panic\n");
    exit(3)
}
