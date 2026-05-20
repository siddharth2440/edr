const std = @import("std");
const events = @import("events.zig");

pub const EventCollector = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    running: bool,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) EventCollector {
        return .{
            .allocator = allocator,
            .io = io,
            .running = false,
        };
    }

    pub fn deinit(self: *EventCollector) !void {
        _ = self;
    }

    pub fn start(self: *EventCollector) !void {
        self.running = true;
        self.start_network_monitor();
        self.start_file_monitor();
    }

    pub fn stop(self: *EventCollector) !void {
        self.running = false;
    }

    fn start_file_monitor(_: *EventCollector) !void {
        const watch_paths = &[_][]const u8{ "/tmp", "/var/tmp", "/dev/shm" };

        for (watch_paths) |path| {
            std.log.info("Monitoring file path: {s}", .{path});
        }

        std.log.info("File monitor started: (inotify)", .{});
    }

    fn start_network_monitor(_: *EventCollector) !void {
        std.log.info("Network monitor started (/proc/net)", .{});
    }
};

const MAX_PROCS = 4096;

pub const ProcMonitor = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) ProcMonitor {
        return .{ .allocator = allocator, .io = io };
    }

    fn scan_process(self: *ProcMonitor) !void {
        var procs = try self.allocator.alloc(events.ProcessEvent, MAX_PROCS);
        errdefer self.allocator.free(procs);

        var count: usize = 0;
        const proc_dir = try std.Io.Dir.openDirAbsolute(self.io, "/proc", .{});
        defer proc_dir.close(self.io);

        var iter = proc_dir.iterate();
        while (try iter.next(self.io)) |entry| {
            if (entry.kind == .directory) {
                const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;

                if (pid > 0 and count < MAX_PROCS) {
                    if (self.read_process_info(pid)) |proc_event| {
                        procs[count] = proc_event;
                        count += 1;
                    }
                }
            }
        }

        return procs[0..count];
    }

    fn read_process_info(self: *ProcMonitor, pid: u32) !events.ProcessEvent {
        var cmdline_buf: [1024]u8 = undefined;

        const exe_link = try std.fmt.allocPrint(self.allocator, "/proc/{d}/exe", .{pid});
        defer self.allocator.free(exe_link);

        var exe_path_buf: [4096]u8 = undefined;

        const exe_path = std.os.linux.readlink(exe_link, &exe_path_buf, exe_path_buf.len);
        std.debug.print("exe_path_data: {any}", .{exe_path});

        const cmdline_file = try std.fmt.allocPrint(self.allocator, "/proc/{}/cmdline", .{pid});
        defer self.allocator.free(cmdline_file);

        const file = try std.Io.Dir.openFileAbsolute(self.io, cmdline_file, .{});
        defer file.close(self.io);

        var filereaderbuf: [4096]u8 = undefined;
        const filereader = file.reader(self.io, &filereaderbuf);
        const reader = &filereader.interface;

        var file_data_buf: [1024]u8 = undefined;
        var file_data = std.ArrayList(u8).initBuffer(&file_data_buf);

        while (true) {
            var buf: [2048]u8 = undefined;
            const bytes_read = reader.readSliceShort(&buf) catch |err| switch (err) {
                error.ReadFailed => return err,
            };
            if (bytes_read == 0) break;

            const data = buf[0..bytes_read];
            try file_data.appendSlice(self.allocator, data);
        }

        var cmdline: []u8 = &.{};
        if (file_data.items.len > 0) {
            for (0..file_data.items.len - 1) |i| {
                if (file_data.items[i] == 0) cmdline_buf[i] = ' ';
            }
            cmdline = cmdline_buf[0 .. file_data.items.len - 1];
        }

        return events.ProcessEvent{
            .pid = pid,
            .ppid = 0,
            .uid = 0,
            .exe_path = exe_path,
            .cmdline = cmdline,
            .cwd = "/",
            .timestamp = std.Io.Clock.real.now(self.io).toMilliseconds(),
        };
    }
};
