const std = @import("std");
const events = @import("events.zig");
const rules = @import("rules.zig");

const DetectionEngine = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    rules_engine: rules.RulesEngine,
    alert_callback: ?*const fn (events.Alert) void,
    stats: DetectionStats,

    pub const DetectionStats = struct {
        total_events: u64 = 0,
        alerts_generated: u64 = 0,
        processes_blocked: u64 = 0,
        files_quarantined: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io) DetectionEngine {
        return .{
            .allocator = allocator,
            .io = io,
            .rules_engine = rules.RulesEngine.init(allocator, io),
            .alert_callback = null,
            .stats = .{},
        };
    }

    pub fn deinit(self: *DetectionEngine) void {
        self.rules_engine.deinit();
    }

    pub fn set_alert_callback(self: *DetectionEngine, callback: *const fn (events.Alert) void) void {
        self.alert_callback = callback;
    }

    pub fn process_event(self: *DetectionEngine, event: events.Event) ?events.Alert {
        self.stats.total_events += 1;

        if (self.rules_engine.evaluate(event)) |matched_rule| {
            const alert = self.create_alert(matched_rule, event);
            self.stats.alerts_generated += 1;

            if (self.alert_callback) |cb| {
                cb(alert);
            }
            return alert;
        }

        return null;
    }

    fn create_alert(self: *DetectionEngine, rule: events.DetectionRule, event: events.Event) events.Alert {
        const pid_val: u32 = switch (event) {
            .process_exec => |e| e.pid,
            .file_create => |e| e.pid,
            .network_connect => |e| e.pid,
            else => 0,
        };

        const process_name: []const u8 = switch (event) {
            .process_exec => |e| std.fs.path.basename(e.exe_path),
            else => "unknown",
        };

        return .{
            .id = self.stats.alerts_generated,
            .timestamp = event.get_timestamp(),
            .rule_name = rule.name,
            .severity = rule.severity,
            .event_type = rule.event_type,
            .message = rule.description,
            .details = null,
            .pid = pid_val,
            .process_name = process_name,
        };
    }
};
