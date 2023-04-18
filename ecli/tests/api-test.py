import os
import time
import subprocess


def list_dir(path):
    subdirectories = []
    for entry in os.scandir(path):
        if entry.is_dir():
            subdirectories.append(entry.path)
    return subdirectories


def run(cmd):
    subprocess.run(cmd, env=env_dbg)


if __name__ == "__main__":
    log_level = "RUST_LOG=info "
    cli_bin = ["ecli/target/release/ecli"]
    server_bin = ["ecli/target/release/eserver"]
    env_dbg = os.environ.copy()
    env_dbg["RUST_LOG"] = "info"
    example_path = "examples/bpftools/"

    examples = map(lambda x: x + "/package.json", list_dir(example_path))

    priv = "sudo"
    for cmdpath in os.environ['PATH'].split(':'):
        if os.path.isdir(cmdpath) and 'doas' in os.listdir(cmdpath):
            priv = "doas"
    server_proc = subprocess.Popen([priv] + server_bin, env=env_dbg)

    # waiting for server start
    time.sleep(1)

    # test start task
    for example in examples:
        cmd = cli_bin + ["client"] + ["start"] + [example]
        run(cmd)

    # test list post
    run(cli_bin + ["client"] + ["list"])

    # test stop post
    run(cli_bin + ["client"] + ["stop"] + ["1", "2", "3"])

    server_proc.kill()
