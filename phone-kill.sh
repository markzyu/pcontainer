#!/bin/bash
TARGET=${1:-dc156}
pid="$(ssh "$TARET" 'ps' | grep dockify | awk '{print $2}')"
echo Pid: $pid
ssh "$TARET" "kill $pid"
ssh "$TARET" "cat log" | grep -m1 -C50 TTIN