# unit test for runtime library

Use Catch2 to write unit tests for the runtime library. See <https://github.com/catchorg/Catch2/blob/devel/docs/tutorial.md> for a tutorial.

## test assets

The test assets are located in the `test/assets` directory. The assets are used to test the runtime library.

- opensnoop: perf event output of `opensnoop` tool
- runqlat: hist map sample of `runqlat` tool
- minimal: minimal test data without any output
- bootstrap: bootstrap test data with ring buffer output
