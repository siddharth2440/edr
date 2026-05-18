const std = @import("std");
const Io = std.Io;

const Config = struct {
    interface: ?[]const u8 = null,
    rules_path: ?[]const u8 = null,
    verbose: bool = null,
    json_output: bool = false,
    daemon_mode: bool = false,
    response_enabled: bool = false,
    log_file: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) !void {
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    var debug_allocator = std.heap.DebugAllocator(.{ .thread_safe = true }).init;
    const allocator = debug_allocator.allocator();
    defer _ = debug_allocator.deinit();

    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    var cfg: Config = .{};

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            print_usage();
            return;
        } else if (std.mem.eql(u8, arg, "-v")) {
            cfg.verbose = true;
        } else if (std.mem.eql(u8, arg, "-j")) {
            cfg.json_output = true;
        } else if (std.mem.eql(u8, arg, "-d")) {
            cfg.daemon_mode = true;
        } else if (std.mem.eql(u8, arg, "-b")) {
            cfg.response_enabled = true;
        } else if (std.mem.eql(u8, arg, "-i")) {
            cfg.interface = true;
        }
    }

    if (cfg.daemon_mode) {
        daemonize();
    }

    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout_writer = &stdout_file_writer.interface;

    try stdout_writer.flush(); // Don't forget to flush!
}

fn daemonize() void {
    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.setsid();
        _ = std.os.linux.fork();
    } else {
        std.os.linux.exit(0);
    }
}

fn print_usage() void {
    std.log.info("SentinelEDR - Endpoint Detection and Response", .{});
    std.log.info("", .{});
    std.log.info("Usage: sentinel-edr [options]", .{});
    std.log.info("", .{});
    std.log.info("Options:", .{});
    std.log.info("  -i, --interface    Network interface for log shipping", .{});
    std.log.info("  -r, --rules        Path to custom rules file", .{});
    std.log.info("  -l, --log          Path to log file", .{});
    std.log.info("  -v, --verbose      Enable verbose output", .{});
    std.log.info("  -j, --json         JSON output format", .{});
    std.log.info("  -d, --daemon       Run in daemon mode", .{});
    std.log.info("  -b, --block        Enable response actions", .{});
    std.log.info("  -h, --help         Show this help", .{});
}
