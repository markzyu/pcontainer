battery_status_summary() {
  pct="$(termux-battery-status | jq .percentage)"
  if [ "$pct" -le 30 ]; then
    # print in red
    echo -n -e "\033[31m[🔌CHARGE ME⚡]\033[0m"
  elif [ "$pct" -ge 70 ]; then
    # print in purple
    echo -n -e "\033[35m[🔌UNPLUG ME⚡]\033[0m"
  else
    # print in green
    echo -n -e "\033[32m[🔋BATT GOOD⚡]\033[0m"
  fi
}

export PS1="\w $(battery_status_summary) \$ "