import os


def run(args):
    return os.system(f"target/debug/dockify {args} 1>/dev/null 2>/dev/null")
