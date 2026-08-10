parent_is_pcontainer() {
  echo "$(ps -o comm= -p $(ps -o ppid= -p $$) | tail -n 1)" | grep -q "/dockify$"
}

battery_status_summary() {
  pct="$(termux-battery-status | jq .percentage)"
  status="$(termux-battery-status | jq -r .status)"
  if [ "$pct" -le 30 ] && [ "$status" != "CHARGING" ]; then
    # print in red
    echo -n -e "\033[31m[🔌CHARGE ME⚡]\033[0m"
  elif [ "$pct" -ge 70 ] && [ "$status" = "CHARGING" ]; then
    # print in purple
    echo -n -e "\033[35m[🔌UNPLUG ME⚡]\033[0m"
  else
    # print in green
    echo -n -e "\033[32m[🔋BATT GOOD🔋]\033[0m"
  fi
}

if ! parent_is_pcontainer; then
  export PS1="\w $(battery_status_summary) \$ "
fi