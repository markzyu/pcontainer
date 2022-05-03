import os
import subprocess as sub


def run(args):
    return os.system(f"target/debug/dockify {args} 1>/dev/null 2>/dev/null")

def run_script(script, timeout=1):
    return sub.run(
        "target/debug/dockify", 
        input=script,
        capture_output=True,
        timeout=timeout,
    )
