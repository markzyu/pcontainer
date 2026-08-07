REPO_DIR="$(dirname "$(dirname "$(realpath "$0")")")"

if [ -z "$1" ]; then
  echo "Usage: $0 <device_ip>"
  exit 1
fi

if ! ping -n 1 -w 1000 "$1"; then
  echo "Device is not reachable: $1"
  exit 1
fi

while true; do
  rsync -av -e "ssh -p 8022" "$REPO_DIR/" user@"$1":pcontainer/ --exclude=target/ --exclude=tests/fixtures/
  sleep 2
done