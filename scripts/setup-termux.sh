if [ -z "$TERMUX_VERSION" ]; then
  echo "This script is meant to be run on the phone. Please run:"
  echo "ssh -p 8022 192.168.xxx.xxx 'bash -s' < $0"
  exit 1
fi

REPO_DIR="$HOME/pcontainer"

pkg install -y jq termux-api git rust python
rm -rf "$REPO_DIR"
git clone https://github.com/markzyu/pcontainer.git "$REPO_DIR"
if ! [ -e "$HOME/.bashrc" ] && ! [ -L "$HOME/.bashrc" ]; then
  ln -s "$REPO_DIR/scripts/.bashrc" ~/.bashrc
fi
