#!/bin/bash
pid="$(ssh dc156 'ps' | grep dockify | awk '{print $2}')"
echo Pid: $pid
ssh dc156 "kill $pid"
ssh dc156 "cat log" | grep -m1 -C50 TTIN