const std = @import("std");
const events = @import("events.zig");

const MAX_RULES = 64;

pub const RulesEngine = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    rules: [MAX_RULES]events.DetectionRule,
    rule_count: usize,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) RulesEngine {
        var engine = RulesEngine{
            .allocator = allocator,
            .io = io,
            .rules = undefined,
            .rule_count = MAX_RULES,
        };

        engine.load_default_rules();
        return engine;
    }

    pub fn deinit(self: *RulesEngine) void {
        _ = self;
    }

    fn load_default_rules(self: *RulesEngine) void {
        const default_rules = [_]events.DetectionRule{
            .{
                .name = "suspecious_process_hidden",
                .description = "Execution of hidden file (starts with .)",
                .severity = events.Severity.medium,
                .event_type = events.EventType.process_exec,
                .pattern = "./",
            },
            .{
                .name = "suspecious_process_temp",
                .description = "Execution from temp directory",
                .severity = events.Severity.high,
                .event_type = events.EventType.process_exec,
                .pattern = "/tmp/",
            },
            .{
                .name = "suspecious_process_dev_shm",
                .description = "Execution from /dev/shm",
                .severity = events.Severity.high,
                .event_type = events.EventType.process_exec,
                .pattern = "/dev/shm",
            },
            .{
                .name = "suspecious_process_wget",
                .description = "Process spawned from wget/curl download",
                .severity = events.Severity.medium,
                .event_type = events.EventType.process_exec,
                .pattern = "wget/curl",
            },
            .{
                .name = "suspecious_process_shell",
                .description = "Process spawned from unusual location",
                .severity = events.Severity.medium,
                .event_type = events.EventType.process_exec,
                .pattern = "/bin/sh",
            },
            .{
                .name = "suspecious_file_write_system",
                .description = "Write to system directory",
                .severity = events.Severity.high,
                .event_type = events.EventType.file_write,
                .pattern = "/etc/",
            },
            .{
                .name = "suspecious_file_temp_exec",
                .description = "Execution file in the temp directory",
                .severity = events.Severity.high,
                .event_type = events.EventType.file_create,
                .pattern = "/tmp/",
            },
            .{
                .name = "suspecious_network_high_port",
                .description = "Connection to unusual high port",
                .severity = events.Severity.low,
                .event_type = events.EventType.network_connect,
                .pattern = ":",
            },
        };

        for (default_rules) |rule| {
            if (self.rule_count < MAX_RULES) {
                self.rules[self.rule_count] = rule;
                self.rule_count += 1;
            }
        }
    }

    pub fn evaluate(self: *RulesEngine, event: events.Event) ?events.DetectionRule {
        for (0..self.rule_count) |i| {
            const rule = self.rules[i];
            if (!rule.enabled) continue;
            if (rule.event_type != @as(events.EventType, @enumFromInt(@intFromEnum(event)))) continue;

            const matches = switch (event) {
                .process_exec => |e| self.matchPattern(rule.pattern, e.exe_path),
                .file_create => |e| self.matchPattern(rule.pattern, e.path),
                .file_write => |e| self.matchPattern(rule.pattern, e.path),
                .network_connect => |e| self.matchPattern(rule.pattern, e.remote_addr),
                else => false,
            };

            if (matches) {
                return rule;
            }
        }

        return null;
    }

    fn match_pattern(self: *RulesEngine, pattern: []const u8, text: []const u8) bool {
        _ = self;
        return std.mem.find(u8, text, pattern) != null;
    }

    fn load_rules_from_file(self: *RulesEngine, path: []const u8) !void {
        const file = try std.Io.Dir.openFileAbsolute(self.io, path, .{});
        defer file.close(self.io);

        var buffer: [1024]u8 = undefined;
        var file_reader = std.Io.File.reader(file, self.io, &buffer);
        var reader = &file_reader.interface;

        // std.Io.Dir.readFileAlloc(dir: Dir, io: Io, sub_path: []const u8, gpa: Allocator, limit: Limit)

        var buf: [1024]u8 = undefined;
        var file_contents = std.ArrayList(u8).initBuffer(&buf);
        defer file_contents.deinit(self.allocator);

        while (true) {
            if (file_reader.atEnd()) break;

            var read_buf: [1024]u8 = undefined;

            // 4. readSliceShort fetches UP TO 1024 bytes from the I/O engine's buffer
            const bytes_read = reader.readSliceShort(&read_buf) catch |err| switch (err) {
                error.ReadFailed => return err,
            };
            if (bytes_read == 0) break;

            const data_we_got = read_buf[0..bytes_read];
            try file_contents.appendSlice(self.allocator, data_we_got);
        }

        var lines = std.mem.splitScalar(u8, file_contents, '\n');

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            if (self.rule_count >= MAX_RULES) break;

            var parts = std.mem.tokenizeScalar(u8, trimmed, '|');
            const name = parts.next() orelse continue;
            const severity_str = parts.next() orelse continue;
            const event_type_str = parts.next() orelse continue;
            const pattern = parts.next() orelse continue;

            const severity = std.meta.stringToEnum(events.Severity, severity_str) orelse .low;
            const eventtype = std.meta.stringToEnum(events.EventType, event_type_str) orelse .process_exec;

            self.rules[self.rule_count] = .{
                .description = name,
                .severity = severity,
                .event_type = eventtype,
                .name = name,
                .pattern = pattern,
            };
            self.rule_count += 1;
        }
    }
};
