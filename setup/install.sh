#!/bin/bash

COMPILE_FROM_SOURCE=0
FORCE_ROOT=0

function usage() {
	echo "Powershell Empire installer"
	echo "USAGE: ./install.sh"
	echo "OPTIONS:"
	echo "  -y    Assume Yes to all questions (install all optional dependencies)"
	echo "  -f    Force install as root (not recommended)"
	echo "  -h    Displays this help text"
}

while getopts "hcyf" option; do
	case "${option}" in
	c) COMPILE_FROM_SOURCE=1 ;;
	y) ASSUME_YES=1 ;;
	f) FORCE_ROOT=1 ;;
	h)
		usage
		exit
		;;
	*)
		;;
	esac
done

function command_exists() {
  command -v "$1" >/dev/null 2>&1;
}

function install_goenv() {
    echo -e "\x1b[1;34m[*] Installing goenv\x1b[0m"

    if [ -d "$HOME/.goenv" ]; then
        echo -e "\x1b[1;32m[+] goenv is already installed in $HOME/.goenv, skipping clone\x1b[0m"
    else
        git clone https://github.com/go-nv/goenv.git ~/.goenv
    fi

    export GOENV_ROOT="$HOME/.goenv"
    export PATH="$GOENV_ROOT/bin:$PATH"
    eval "$(goenv init -)"

    echo 'export GOENV_ROOT="$HOME/.goenv"' >> ~/.bashrc
    echo 'export PATH="$GOENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(goenv init -)"' >> ~/.bashrc

    echo 'export GOENV_ROOT="$HOME/.goenv"' >> ~/.zshrc
    echo 'export PATH="$GOENV_ROOT/bin:$PATH"' >> ~/.zshrc
    echo 'eval "$(goenv init -)"' >> ~/.zshrc

    # These are for the Docker builds since
    # the bashrc and zshrc files are not sourced
    sudo ln -s $HOME/.goenv/shims/go /usr/bin/go || true
    sudo ln -s $HOME/.goenv/shims/gofmt /usr/bin/gofmt || true
    sudo ln -s $HOME/.goenv/bin/goenv /usr/bin/goenv || true
}

function update_goenv() {
  echo -e "\x1b[1;34m[*] Updating goenv\x1b[0m"

  cd $GOENV_ROOT && git fetch --all && git pull && cd -
}

function install_go() {
  echo -e "\x1b[1;34m[*] Installing Go\x1b[0m"

  goenv install $(cat .go-version) -s
}

function install_pyenv() {
  echo -e "\x1b[1;34m[*] Installing pyenv\x1b[0m"

  curl https://pyenv.run | bash

  export PYENV_ROOT="$HOME/.pyenv"
  command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
  eval "$(pyenv init -)"

  echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
  echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
  echo 'eval "$(pyenv init -)"' >> ~/.bashrc

  echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
  echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
  echo 'eval "$(pyenv init -)"' >> ~/.zshrc

  sudo ln -s $HOME/.pyenv/bin/pyenv /usr/bin/pyenv
}

function update_pyenv() {
  echo -e "\x1b[1;34m[*] Updating pyenv\x1b[0m"

  cd $PYENV_ROOT && git fetch --all && git pull && cd -
}

function install_python() {
  echo -e "\x1b[1;34m[*] Installing Python\x1b[0m"

  sudo DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
  apt-get install -y build-essential gdb lcov pkg-config \
    libbz2-dev libffi-dev libgdbm-dev libgdbm-compat-dev liblzma-dev \
    libncurses5-dev libreadline6-dev libsqlite3-dev libssl-dev \
    lzma tk-dev uuid-dev zlib1g-dev

  pyenv install $(cat .python-version) -s
}

function install_poetry() {
  echo -e "\x1b[1;34m[*] Installing Poetry\x1b[0m"

  curl -sSL https://install.python-poetry.org | python3 -
  export PATH="$HOME/.local/bin:$PATH"
  echo "export PATH=$HOME/.local/bin:$PATH" >> ~/.bashrc
  echo "export PATH=$HOME/.local/bin:$PATH" >> ~/.zshrc
  sudo ln -s $HOME/.local/bin/poetry /usr/bin
}

function install_powershell() {
  echo -e "\x1b[1;34m[*] Installing PowerShell\x1b[0m"
  # To deal with the following error:
  # Couldn't find a valid ICU package installed on the system.
  # Please install libicu (or icu-libs) using your package manager and try again.
  sudo apt-get install -y libicu-dev

  # https://learn.microsoft.com/en-us/powershell/scripting/install/install-other-linux?view=powershell-7.4#binary-archives
  ARCH=$(uname -m)
  if [ "$ARCH" == "x86_64" ]; then
    POWERSHELL_URL="https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-x64.tar.gz"
  else
    POWERSHELL_URL="https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-arm64.tar.gz"
  fi

  curl -L -o /tmp/powershell.tar.gz $POWERSHELL_URL
  sudo mkdir -p /opt/microsoft/powershell/7
  sudo tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7
  sudo chmod +x /opt/microsoft/powershell/7/pwsh
  sudo ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh
}

function get_architecture() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            echo "linux-x64"
            ;;
        aarch64 | arm64)
            echo "linux-arm64"
            ;;
        *)
            echo "unsupported"
            ;;
    esac
}

function install_mysql() {
  echo -e "\x1b[1;34m[*] Installing MySQL\x1b[0m"
  # https://imsavva.com/silent-installation-mysql-5-7-on-ubuntu/
  # http://www.microhowto.info/howto/perform_an_unattended_installation_of_a_debian_package.html
  echo mysql-apt-config mysql-apt-config/enable-repo select mysql-8.0 | sudo debconf-set-selections
  echo mysql-community-server mysql-server/default-auth-override select "Use Strong Password Encryption (RECOMMENDED)" | sudo debconf-set-selections

  if [ "$OS_NAME" == "UBUNTU" ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server
  elif [[ "$OS_NAME" == "KALI" || "$OS_NAME" == "PARROT" || "$OS_NAME" == "DEBIAN" ]]; then
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y default-mysql-server # mariadb
  fi

  echo -e "\x1b[1;34m[*] Starting MySQL\x1b[0m"
}

function start_mysql() {
  echo -e "\x1b[1;34m[*] Configuring MySQL\x1b[0m"
  sudo systemctl start mysql.service || true # will fail in a docker image

  # Add the default empire user to the mysql database
  sudo mysql -u root -e "CREATE USER IF NOT EXISTS 'empire_user'@'localhost' IDENTIFIED BY 'empire_password';" || true
  sudo mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO 'empire_user'@'localhost' WITH GRANT OPTION;" || true
  sudo mysql -u root -e "FLUSH PRIVILEGES;" || true

  # Some OS have a root password set by default. We could probably
  # be more smart about this, but we just try both.
  sudo mysql -u root -proot -e "CREATE USER IF NOT EXISTS 'empire_user'@'localhost' IDENTIFIED BY 'empire_password';" || true
  sudo mysql -u root -proot -e "GRANT ALL PRIVILEGES ON *.* TO 'empire_user'@'localhost' WITH GRANT OPTION;" || true
  sudo mysql -u root -proot -e "FLUSH PRIVILEGES;" || true

  if [ "$ASSUME_YES" == "1" ]; then
    answer="Y"
  else
    echo -n -e "\x1b[1;33m[>] Do you want to enable MySQL to start on boot? (y/N)? \x1b[0m"
    read -r answer
  fi

  if [[ "$answer" =~ ^[Yy]$ ]]; then
    sudo systemctl enable mysql || true
  fi
}

set -e

if [ "$EUID" -eq 0 ]; then
  if grep -q docker /proc/1/cgroup; then
    echo "This script is being run in a Docker build context."
  elif [ "$FORCE_ROOT" -eq 1 ]; then
    echo -e "\x1b[1;33m[!] Warning: Running as root is not recommended.\x1b[0m"
  else
    echo -e "\x1b[1;31m[!] This script should not be run as root. Use the -f option to force installation as root (not recommended).\x1b[0m"
    exit 1
  fi
fi

sudo apt-get update && sudo apt-get install -y wget git lsb-release curl

sudo -v

# https://stackoverflow.com/questions/24112727/relative-paths-based-on-file-location-instead-of-current-working-directory
PARENT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; cd .. ; pwd -P )
OS_NAME=
VERSION_ID=
if VERSION_ID=$(grep -oP '^(11|12)' /etc/debian_version 2>/dev/null); then
  echo -e "\x1b[1;34m[*] Detected Debian $VERSION_ID\x1b[0m"
  OS_NAME="DEBIAN"
elif grep -i "NAME=\"Ubuntu\"" /etc/os-release 2>/dev/null; then
  OS_NAME=UBUNTU
  VERSION_ID=$(grep -i VERSION_ID /etc/os-release | grep -o -E "[[:digit:]]+\\.[[:digit:]]+")
  if [[ "$VERSION_ID" == "20.04" || "$VERSION_ID" == "22.04" || "$VERSION_ID" == "24.04" ]]; then
    echo -e "\x1b[1;34m[*] Detected Ubuntu ${VERSION_ID}\x1b[0m"
  else
    echo -e '\x1b[1;31m[!] Ubuntu must be 20.04, 22.04, or 24.04 \x1b[0m' && exit
  fi
elif grep -i "Kali" /etc/os-release 2>/dev/null; then
  echo -e "\x1b[1;34m[*] Detected Kali\x1b[0m"
  OS_NAME=KALI
  VERSION_ID=KALI_ROLLING
elif grep -i "Parrot" /etc/os-release 2>/dev/null; then
  OS_NAME=PARROT
  VERSION_ID=$(grep -i VERSION_ID /etc/os-release | grep -o -E [[:digit:]]+\\.[[:digit:]]+)
else
  echo -e '\x1b[1;31m[!] Unsupported OS. Exiting.\x1b[0m' && exit
fi

sudo apt-get update
# libpango-1.0-0 and libharfbuzz0b for weasyprint
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 \
  libpango-1.0-0 \
  libharfbuzz0b \
  libpangoft2-1.0-0

if ! command_exists pwsh; then
  install_powershell
fi

if ! command_exists goenv; then
  install_goenv
else
  update_goenv
fi

install_go

if ! command_exists mysql; then
  install_mysql
fi

start_mysql

if [ "$ASSUME_YES" == "1" ] ;then
  answer="Y"
else
  echo -n -e "\x1b[1;33m[>] Do you want to install OpenJDK? It is only needed to generate a .jar stager (y/N)? \x1b[0m"
  read -r answer
fi
if [ "$answer" != "${answer#[Yy]}" ] ;then
  echo -e "\x1b[1;34m[*] Installing OpenJDK\x1b[0m"
  sudo apt-get install -y default-jdk
else
  echo -e "\x1b[1;34m[*] Skipping OpenJDK\x1b[0m"
fi

# https://github.com/python-poetry/poetry/issues/1917#issuecomment-1235998997
export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
echo -e "\x1b[1;34m[*] Checking Python version\x1b[0m"

# Ubuntu 22.04 - 3.10, 20.04 - 3.8
# Debian 10 - 3.7, 11 - 3.9, 12 - 3.11
# Kali and Parrot do not have a reliable version
if ! command_exists pyenv; then
  install_pyenv
else
  update_pyenv
fi

install_python

if ! command_exists poetry; then
  install_poetry
fi

echo -e "\x1b[1;34m[*] Installing Packages\x1b[0m"
poetry config virtualenvs.in-project true
poetry install

echo -e '\x1b[1;32m[+] Install Complete!\x1b[0m'
echo -e ''
echo -e '\x1b[1;32m[+] Run the following command to start Empire\x1b[0m'
echo -e '\x1b[1;34m[*] ./ps-empire server\x1b[0m'
