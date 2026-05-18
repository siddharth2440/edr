const std = @import("std");
const events = @import("events.zig");

pub const AlertLogger = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: ?std.Io.File,
    json_output: bool,
    verbose: bool,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) AlertLogger {
        return .{
            .allocator = allocator,
            .io = io,
            .file = null,
            .json_output = false,
            .verbose = false,
        };
    }

    pub fn deinit(self: *AlertLogger) !void {
        if (self.file) |f| {
            f.close(self.io);
        }
    }

    pub fn open_log_file(self: *AlertLogger, path: []const u8) !void {
        self.file = try std.Io.Dir.openFileAbsolute(self.io, path, .{});
    }

    fn log_text(self: *AlertLogger, alert: events.Alert) !void {
        const severity_str = switch (alert.severity) {
            .info => "INFO",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .critical => "CRITICAL",
        };

        if (self.file) |f| {
            const line = std.fmt.allocPrint(self.allocator, "[{}] {s} - {s}: {s} (PID: {})\n", .{ alert.timestamp, severity_str, alert.rule_name, alert.message, alert.pid }) catch return;
            defer self.allocator.free(line);

            var file_writer_buf: [1024]u8 = undefined;
            var file_writer = f.writer(self.io, &file_writer_buf);

            try file_writer.interface.writeAll(line);
            try file_writer.flush(); // Never Ever Forget to Flush.
        }
    }
};
