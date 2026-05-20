const std = @import("std");
const events = @import("events.zig");
const alerts = @import("alerts.zig");

pub const Response = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    enabled: true,
    quarantine_dir: []const u8,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, enabled: bool) Response {
        return .{
            .allocator = allocator,
            .io = io,
            .enabled = enabled,
            .quarantine_dir = "/var/lib/sentinel-edr/quarantine",
        };
    }

    fn set_enabled(self: *Response) void {
        self.enabled = true;
    }

    fn respond(self: *Response, alert: events.Alert) !void {
        if (!self.enabled) return;

        switch (alert.severity) {
            .critical, .high => {
                try self.terminate_process(alert.pid);
            },
            .medium => {
                try self.quarantine_process();
            },
            else => {},
        }
    }

    fn terminate_process(self: *Response, pid: u32) !void {
        if (!self.enabled) return;
        if (pid == 0 or pid == 1) return;

        std.log.warn("Terminating malicious process: {d}", .{pid});

        std.posix.kill(@intCast(pid), std.posix.SIG.KILL) catch {
            std.log.warn("Failed to terminate process {}", .{pid});
            return;
        };

        std.log.info("Process {} terminated successfully", .{pid});
    }

    fn quarantine_process(self: *Response) !void {
        if (!self.enabled) return;
        std.log.warn("Quarantine not available - process detected", .{});
    }

    pub fn blockip(self: *Response, ip: []const u8) !void {
        if (!self.enabled) return;

        std.log.warn("Blocking Ip Address: {s}", .{ip});
        const iptables_cmd = try std.fmt.allocPrint(self.allocator, "iptables -I INPUT -s {s} -j DROP", .{ip});
        defer self.allocator.free(iptables_cmd);

        std.log.info("Would execute: {s}", .{iptables_cmd});
    }

    fn init_quarantine_dir(self: *Response) !void {
        return std.Io.Dir.createDirAbsolute(self.io, self.quarantine_dir);
    }
};
