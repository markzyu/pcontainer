import os
import subprocess as sub


STAGING = "tests/fixtures/staging"


def run(args, **kwargs):
    cmd = " ".join(_get_cmd(**kwargs))
    return os.system(f"{cmd} {args} 1>/dev/null 2>/dev/null")


def run_script(script, timeout=5, **kwargs):
    cmd = _get_cmd(**kwargs)
    print(f"cmd = {cmd}")
    return sub.run(
        cmd, 
        input=script,
        timeout=timeout,
        stdout=sub.PIPE,
        stderr=os.sys.stderr,
    )


def _get_cmd(root=False, rootfs=False):
    args = [
        "target/debug/dockify",
        "--root" if root else "",
        "--rootfs" if rootfs else "",
        STAGING if rootfs else "",
    ]
    return list(filter(bool, args))
