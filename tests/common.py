import os
import subprocess as sub


def run(args, **kwargs):
    cmd = " ".join(_get_cmd(**kwargs))
    return os.system(f"{cmd} {args} 1>/dev/null 2>/dev/null")


def run_script(script, timeout=1, **kwargs):
    cmd = _get_cmd(**kwargs)
    return sub.run(
        cmd, 
        input=script,
        capture_output=True,
        timeout=timeout,
    )


def _get_cmd(root=False):
    args = [
        "target/debug/dockify",
        "--root" if root else "",
    ]
    return list(filter(bool, args))
