import os
import subprocess as sub


STAGING = "tests/fixtures/staging"


def run(args, **kwargs):
    cmd = " ".join(_get_cmd(**kwargs))
    return os.system(f"{cmd} {args} 1>/dev/null 2>/dev/null")


def run_script(script, timeout=5, stderr=None, **kwargs):
    cmd = _get_cmd(**kwargs)
    cmd_expr = " ".join(cmd)
    print(f"cmd = {cmd_expr} script = {script.strip()}")
    return sub.run(
        cmd, 
        input=script,
        timeout=timeout,
        stdout=sub.PIPE,
        stderr=stderr or os.sys.stderr,
    )


def _get_cmd(root=False, rootfs=False):
    args = [
        "target/debug/dockify",
        "--root" if root else "",
        "--rootfs" if rootfs else "",
        STAGING if rootfs else "",
    ]
    return list(filter(bool, args))
