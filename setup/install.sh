#!/bin/bash

function usage() {
	echo "Powershell Empire installer"
	echo "USAGE: ./install.sh"
	echo "OPTIONS:"
	echo "  -y    Assume Yes to all questions (install all optional dependencies)"
	echo "  -h    Displays this help text"
}

while getopts "hy" option; do
	case "${option}" in
	y) ASSUME_YES=1 ;;
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
function install_powershell() {
  echo -e "\x1b[1;34m[*] Installing PowerShell\x1b[0m"
  if [ "$OS_NAME" == "DEBIAN" ]; then
    # TODO Temporary until official Debian 12 support is added
    VERSION_ID_2=$VERSION_ID
    if [ "$VERSION_ID" == "12" ]; then
      VERSION_ID_2="11"
    fi
    wget https://packages.microsoft.com/config/debian/"${VERSION_ID_2}"/packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb
    sudo apt-get update
    sudo apt-get install -y powershell
  elif [ "$OS_NAME" == "UBUNTU" ]; then
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y wget apt-transport-https software-properties-common
    wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb"
    sudo dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb
    sudo apt-get update
    sudo apt-get install -y powershell
  elif [ "$OS_NAME" == "KALI" ]; then
    sudo apt-get update && sudo apt-get -y install powershell
  elif [ $OS_NAME == "PARROT" ]; then
    sudo apt-get update && sudo apt-get -y install powershell
  fi

  sudo mkdir -p /usr/local/share/powershell/Modules
  sudo cp -r "$PARENT_PATH"/empire/server/data/Invoke-Obfuscation /usr/local/share/powershell/Modules
  rm -f packages-microsoft-prod.deb*
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
  sudo systemctl start mysqld.service || true # will fail in a docker image

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

function install_xar() {
  # xar-1.6.1 has an incompatibility with libssl 1.1.x that is patched here
  wget https://github.com/BC-SECURITY/xar/archive/xar-1.6.1-patch.tar.gz
  rm -rf xar-1.6.1
  rm -rf xar-1.6.1-patch/xar
  rm -rf xar-xar-1.6.1-patch
  tar -xvf xar-1.6.1-patch.tar.gz && mv xar-xar-1.6.1-patch/xar/ xar-1.6.1/
  (cd xar-1.6.1 && ./autogen.sh)
  (cd xar-1.6.1 && ./configure)
  (cd xar-1.6.1 && make)
  (cd xar-1.6.1 && sudo make install)
  rm -rf xar-1.6.1
  rm -rf xar-1.6.1-patch/xar
  rm -rf xar-xar-1.6.1-patch
}

function install_bomutils() {
  rm -rf bomutils
  git clone https://github.com/BC-SECURITY/bomutils.git
  (cd bomutils && make)
  (cd bomutils && sudo make install)
  chmod 755 bomutils/build/bin/mkbom && sudo cp bomutils/build/bin/mkbom /usr/local/bin/.
  rm -rf bomutils
}

function install_dotnet() {
  echo -e "\x1b[1;34m[*] Installing dotnet for C# agents and modules\x1b[0m"
  if [ $OS_NAME == "UBUNTU" ]; then
    wget https://packages.microsoft.com/config/ubuntu/"${VERSION_ID}"/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb

    # If version is 22.04, we need to write an /etc/apt/preferences file
    # https://github.com/dotnet/core/issues/7699
    if [ "$VERSION_ID" == "22.04" ]; then
      echo -e "\x1b[1;34m[*] Detected Ubuntu 22.04, writing /etc/apt/preferences file\x1b[0m"
      sudo tee -a /etc/apt/preferences <<EOT
Package: *
Pin: origin "packages.microsoft.com"
Pin-Priority: 100
EOT
    fi

    sudo apt-get update
    sudo apt-get install -y apt-transport-https dotnet-sdk-6.0
  elif [ $OS_NAME == "DEBIAN" ]; then
    wget https://packages.microsoft.com/config/debian/"${VERSION_ID}"/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    sudo apt-get update
    sudo apt-get install -y apt-transport-https dotnet-sdk-6.0
  else
    wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    sudo apt-get update
    sudo apt-get install -y apt-transport-https dotnet-sdk-6.0
  fi
}

function install_nim() {
  if [ "$ASSUME_YES" == "1" ] ;then
    answer="Y"
  else
    echo -n -e "\x1b[1;33m[>] Do you want to install Nim and MinGW? It is only needed to generate a Nim stager (y/N)? \x1b[0m"
    read -r answer
  fi
  if [ "$answer" != "${answer#[Yy]}" ]; then
    sudo apt-get install -y curl git gcc xz-utils
    export CHOOSENIM_CHOOSE_VERSION=1.6.12
    curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
    echo "export PATH=$HOME/.nimble/bin:$PATH" >> ~/.bashrc
    echo "export PATH=$HOME/.nimble/bin:$PATH" >> ~/.zshrc
    export PATH=$HOME/.nimble/bin:$PATH
    sudo ln -s $HOME/.nimble/bin/* /usr/bin/
    nimble install -y nimble@0.14.2
    nimble install -y winim zippy nimcrypto
    sudo apt-get install -y mingw-w64
  else
    echo -e "\x1b[1;34m[*] Skipping Nim\x1b[0m"
  fi
}

set -e

if [ "$EUID" -eq 0 ]; then
  if grep -q docker /proc/1/cgroup; then
    echo "This script is being run in a Docker build context."
  else
    echo "This script should not be run as root."
    exit 1
  fi
fi
sudo apt-get update && sudo apt-get install -y wget git lsb-release curl

sudo -v

# https://stackoverflow.com/questions/24112727/relative-paths-based-on-file-location-instead-of-current-working-directory
PARENT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; cd .. ; pwd -P )
OS_NAME=
VERSION_ID=
if VERSION_ID=$(grep -oP '^(10|11|12)' /etc/debian_version 2>/dev/null); then
  echo -e "\x1b[1;34m[*] Detected Debian $VERSION_ID\x1b[0m"
  OS_NAME="DEBIAN"
elif grep -i "NAME=\"Ubuntu\"" /etc/os-release 2>/dev/null; then
  OS_NAME=UBUNTU
  VERSION_ID=$(grep -i VERSION_ID /etc/os-release | grep -o -E "[[:digit:]]+\\.[[:digit:]]+")
  if [[ "$VERSION_ID" == "20.04" || "$VERSION_ID" == "22.04" ]]; then
    echo -e "\x1b[1;34m[*] Detected Ubuntu ${VERSION_ID}\x1b[0m"
  else
    echo -e '\x1b[1;31m[!] Ubuntu must be 20.04 or 22.04\x1b[0m' && exit
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
# xclip for copying to clipboard
# libpango-1.0-0 and libharfbuzz0b for weasyprint
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 \
  xclip \
  libpango-1.0-0 \
  libharfbuzz0b \
  libpangoft2-1.0-0

if ! command_exists pwsh; then
  install_powershell
fi

if ! command_exists dotnet; then
  install_dotnet
fi

if ! command_exists nim; then
  install_nim
fi

if ! command_exists mysql; then
  install_mysql
fi

start_mysql

if [ "$ASSUME_YES" == "1" ] ;then
  answer="Y"
else
  echo -n -e "\x1b[1;33m[>] Do you want to install xar and bomutils? They are only needed to generate a .dmg stager (y/N)? \x1b[0m"
  read -r answer
fi
if [ "$answer" != "${answer#[Yy]}" ] ;then
  sudo apt-get install -y make autoconf g++ git zlib1g-dev libxml2-dev libssl-dev
  install_xar
  install_bomutils
else
    echo -e "\x1b[1;34m[*] Skipping xar and bomutils\x1b[0m"
fi

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

  sudo DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
    apt-get -y install build-essential gdb lcov pkg-config \
      libbz2-dev libffi-dev libgdbm-dev libgdbm-compat-dev liblzma-dev \
      libncurses5-dev libreadline6-dev libsqlite3-dev libssl-dev \
      lzma lzma-dev tk-dev uuid-dev zlib1g-dev

  pyenv install 3.12.2
fi

if ! command_exists poetry; then
  curl -sSL https://install.python-poetry.org | python3 -
  export PATH="$HOME/.local/bin:$PATH"
  echo "export PATH=$HOME/.local/bin:$PATH" >> ~/.bashrc
  echo "export PATH=$HOME/.local/bin:$PATH" >> ~/.zshrc
  sudo ln -s $HOME/.local/bin/poetry /usr/bin
fi

echo -e "\x1b[1;34m[*] Installing Packages\x1b[0m"
poetry config virtualenvs.in-project true
poetry config virtualenvs.prefer-active-python true
poetry install

echo -e '\x1b[1;32m[+] Install Complete!\x1b[0m'
echo -e ''
echo -e '\x1b[1;32m[+] Run the following commands in separate terminals to start Empire\x1b[0m'
echo -e '\x1b[1;34m[*] ./ps-empire server\x1b[0m'
echo -e '\x1b[1;34m[*] ./ps-empire client\x1b[0m'
