MINDER_PID_FILE="$HOME/.shutdown_minder.pid"
MINDER_TIMER_FILE="$HOME/.shutdown_minder.timer"
MINDER_DELAY=600

start_or_replace_shutdown_minder() {
  let new_timer=$(date +%s)+$MINDER_DELAY;
  echo "$new_timer" > "$MINDER_TIMER_FILE"
  if [ -f "$MINDER_PID_FILE" ]; then
    exit 0
  fi

  echo "$$" > "$MINDER_PID_FILE"
  while [ -f "$MINDER_TIMER_FILE" ] && [ "$(date +%s)" -lt "$(cat "$MINDER_TIMER_FILE")" ]; do
    sleep 1
  done
  rm "$MINDER_PID_FILE" 2>/dev/null

  if ! [ -f "$MINDER_TIMER_FILE" ]; then
    exit 0
  fi
  rm "$MINDER_TIMER_FILE" 2>/dev/null

  termux-volume music 20
  termux-tts-speak "This is a reminder to turn off your developer phone."
  termux-volume music 0
}

start_or_replace_shutdown_minder &