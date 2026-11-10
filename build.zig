const std = @import("std");
pub fn build(b: *std.Build) void {
    const sdk_build = b.lazyImport(@This(), "r4os_sdk") orelse return;
    const sdk_dep = b.dependencyFromBuildZig(sdk_build, .{});
    const sdk = sdk_build.sdk(b, sdk_dep, .{});
    _ = sdk.addR4MF(b.path("module.R4MF"));
    const unit = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("src/neighbor_tests.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }) });
    unit.root_module.addImport("r4os", sdk.createR4osModule(b.graph.host, .ReleaseSafe));
    b.step("test", "Run bounded ND syntax and neighbor lifetime cases").dependOn(&b.addRunArtifact(unit).step);
}
