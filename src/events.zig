const std = @import("std");

pub const EventType = enum(u8) {
    process_exec = 1,
    process_fork,
    process_exit,
    process_setuid,
    file_create,
    file_write,
    file_delete,
    file_rename,
    file_chmod,
    file_open,
    network_connect,
    network_listen,
    network_accept,
    network_close,
};

pub const Severity = enum(u8) {
    info = 1,
    low,
    medium,
    high,
    critical,
};

pub const ProcessEvent = struct {
    pid: u32,
    ppid: u32,
    uid: u32,
    exe_path: []const u8,
    cmdline: []const u8,
    cwd: []const u8,
    timestamp: i64,
};

pub const FileEvent = struct {
    pid: u32,
    path: []const u8,
    new_path: ?[]const u8 = null,
    mode: u16,
    timestamp: u64,
};

pub const NetworkEvent = struct {
    pid: u32,
    local_addr: []const u8,
    remote_addr: []const u8,
    local_port: u16,
    remote_port: u16,
    protocol: []const u16,
    state: []const u16,
    timestamp: u64,
};

pub const Event = union(EventType) {
    process_exec: ProcessEvent,
    process_fork: ProcessEvent,
    process_exit: ProcessEvent,
    process_setuid: ProcessEvent,
    file_create: FileEvent,
    file_write: FileEvent,
    file_delete: FileEvent,
    file_rename: FileEvent,
    file_chmod: FileEvent,
    file_open: FileEvent,
    network_connect: NetworkEvent,
    network_listen: NetworkEvent,
    network_accept: NetworkEvent,
    network_close: NetworkEvent,

    pub fn get_timestamp(self: Event) i64 {
        return switch (self) {
            .process_exec => |e| e.timestamp,
            .process_fork => |e| e.timestamp,
            .process_exit => |e| e.timestamp,
            .process_setuid => |e| e.timestamp,
            .file_create => |e| e.timestamp,
            .file_write => |e| e.timestamp,
            .file_delete => |e| e.timestamp,
            .file_rename => |e| e.timestamp,
            .file_chmod => |e| e.timestamp,
            .file_open => |e| e.timestamp,
            .network_connect => |e| e.timestamp,
            .network_listen => |e| e.timestamp,
            .network_accept => |e| e.timestamp,
            .network_close => |e| e.timestamp,
        };
    }
};

pub const Alert = struct {
    id: u64,
    timestamp: i64,
    rule_name: []const u8,
    severity: Severity,
    event_type: EventType,
    message: []const u8,
    details: std.StringHashMap([]const u8),
    pid: u32,
    process_name: []const u8,
};
