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
    wget https://packages.microsoft.com/config/debian/"${VERSION_ID}"/packages-microsoft-prod.deb
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
    apt update && apt -y install powershell
  elif [ $OS_NAME == "PARROT" ]; then
    apt update && apt -y install powershell
  fi

  mkdir -p /usr/local/share/powershell/Modules
  cp -r "$PARENT_PATH"/empire/server/data/Invoke-Obfuscation /usr/local/share/powershell/Modules
  rm -f packages-microsoft-prod.deb*
}

function install_mysql() {
  echo -e "\x1b[1;34m[*] Installing MySQL\x1b[0m"
  # https://imsavva.com/silent-installation-mysql-5-7-on-ubuntu/
  # http://www.microhowto.info/howto/perform_an_unattended_installation_of_a_debian_package.html
  echo mysql-apt-config mysql-apt-config/enable-repo select mysql-8.0 | sudo debconf-set-selections
  echo mysql-community-server mysql-server/default-auth-override select "Use Strong Password Encryption (RECOMMENDED)" | sudo debconf-set-selections

  if [ "$OS_NAME" == "UBUNTU" ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt install -y mysql-server
  elif [[ "$OS_NAME" == "KALI" || "$OS_NAME" == "PARROT" || "$OS_NAME" == "DEBIAN" ]]; then
    sudo apt update
    sudo DEBIAN_FRONTEND=noninteractive apt install -y default-mysql-server # mariadb
  fi

  echo -e "\x1b[1;34m[*] Starting MySQL\x1b[0m"
}

function start_mysql() {
  sudo systemctl start mysql.service || true # will fail in a docker image

  # Add the default empire user to the mysql database
  mysql -u root -e "CREATE USER IF NOT EXISTS 'empire_user'@'localhost' IDENTIFIED BY 'empire_password';" || true
  mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO 'empire_user'@'localhost' WITH GRANT OPTION;" || true
  mysql -u root -e "FLUSH PRIVILEGES;" || true

  # Some OS have a root password set by default. We could probably
  # be more smart about this, but we just try both.
  mysql -u root -proot -e "CREATE USER IF NOT EXISTS 'empire_user'@'localhost' IDENTIFIED BY 'empire_password';" || true
  mysql -u root -proot -e "GRANT ALL PRIVILEGES ON *.* TO 'empire_user'@'localhost' WITH GRANT OPTION;" || true
  mysql -u root -proot -e "FLUSH PRIVILEGES;" || true
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

export DEBIAN_FRONTEND=noninteractive
set -e

apt-get update && apt-get install -y wget sudo git lsb-release

sudo -v

# https://stackoverflow.com/questions/24112727/relative-paths-based-on-file-location-instead-of-current-working-directory
PARENT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; cd .. ; pwd -P )
OS_NAME=
VERSION_ID=
if grep "10.*" /etc/debian_version 2>/dev/null; then
  echo -e "\x1b[1;34m[*] Detected Debian 10\x1b[0m"
  OS_NAME="DEBIAN"
  VERSION_ID="10"
elif grep "11.*" /etc/debian_version 2>/dev/null; then
  echo -e "\x1b[1;34m[*] Detected Debian 11\x1b[0m"
  OS_NAME="DEBIAN"
  VERSION_ID="11"
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
sudo apt-get install -y python3-dev python3-pip xclip

install_powershell

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
else
  wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
  sudo dpkg -i packages-microsoft-prod.deb
  sudo apt-get update
  sudo apt-get install -y apt-transport-https dotnet-sdk-6.0
fi

if [ "$ASSUME_YES" == "1" ] ;then
  answer="Y"
else
  echo -n -e "\x1b[1;33m[>] Do you want to install Nim and MinGW? It is only needed to generate a Nim stager (y/N)? \x1b[0m"
  read -r answer
fi
if [ "$answer" != "${answer#[Yy]}" ] ;then
  sudo apt install -y curl git gcc
  export CHOOSENIM_CHOOSE_VERSION=1.6.12
  curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
  echo "export PATH=/root/.nimble/bin:$PATH" >> ~/.bashrc
  export PATH=/root/.nimble/bin:$PATH
  SOURCE_MESSAGE=true
  nimble install -y nimble@0.14.2
  nimble install -y winim zippy nimcrypto
  sudo apt install -y mingw-w64
else
  echo -e "\x1b[1;34m[*] Skipping Nim\x1b[0m"
fi

if [ "$OS_NAME" == "PARROT" ]; then
  # https://github.com/python-poetry/poetry/issues/1917#issuecomment-1235998997
  export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
fi
echo -e "\x1b[1;34m[*] Checking Python version\x1b[0m"
python_version=($(python3 -c 'import sys; print("{} {}".format(sys.version_info.major, sys.version_info.minor))'))
if [ "${python_version[0]}" -eq 3 ] && [ "${python_version[1]}" -lt 8 ]; then
  if ! command_exists python3.8; then
    if [ "$OS_NAME" == "UBUNTU" ]; then
      echo -e "\x1b[1;34m[*] Python3 version less than 3.8, installing 3.8\x1b[0m"
      sudo apt-get install -y python3.8 python3.8-dev python3-pip
    elif [ "$OS_NAME" == "DEBIAN" ]; then
      echo -e "\x1b[1;34m[*] Python3 version less than 3.8, installing 3.8\x1b[0m"
      if [ "$ASSUME_YES" == "1" ] ;then
        answer="Y"
      else
        echo -n -e "\x1b[1;33m[>] Python 3.8 must be built from source. This might take a bit, do you want to continue (y/N)? \x1b[0m"
        read -r answer
      fi
      if [ "$answer" != "${answer#[Yy]}" ] ;then
        sudo apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl libbz2-dev
        curl -O https://www.python.org/ftp/python/3.8.16/Python-3.8.16.tar.xz
        tar -xf Python-3.8.16.tar.xz
        cd Python-3.8.16
        ./configure --enable-optimizations
        make -j"$(nproc)"
        sudo make altinstall
        cd ..
        rm -rf Python-3.8.16
        rm Python-3.8.16.tar.xz
      else
        echo -e "Abort"
        exit
      fi
    fi
  fi
  # TODO: We should really use the official poetry installer, but since right now we
  #  recommend running this script as sudo, it installs poetry in a way that you can't
  #  run it without sudo su. We should probably update the script to not be run as sudo,
  #  and only use sudo when needed within the script itself.
  python3.8 -m pip install poetry
else
  if [ "${python_version[0]}" -eq 3 ] && [ "${python_version[1]}" -ge 11 ]; then
    # Select python3-poetry if OS is Kali
    if [ "$OS_NAME" == "KALI" ]; then
      echo -e "\x1b[1;34m[*] Detected Kali; Installing python3-poetry from Kali repos\x1b[0m"
      sudo apt-get -y install python3-poetry
    else
      python3 -m pip install poetry --break-system-packages
    fi
  else
    python3 -m pip install poetry
  fi
fi

echo -e "\x1b[1;34m[*] Installing Packages\x1b[0m"
# Perform unprivileged configuration and installation for poetry if OS is Kali
if [ "$OS_NAME" == "KALI" ]; then
  GITROOT=$(git rev-parse --show-toplevel)
  runuser - $USER -c "poetry -C $GITROOT config virtualenvs.in-project true"
  runuser - $USER -c "poetry -C $GITROOT install"
else
  poetry config virtualenvs.in-project true
  poetry install
fi

echo -e '\x1b[1;32m[+] Install Complete!\x1b[0m'
echo -e ''
echo -e '\x1b[1;32m[+] Run the following commands in separate terminals to start Empire\x1b[0m'
echo -e '\x1b[1;34m[*] ./ps-empire server\x1b[0m'
echo -e '\x1b[1;34m[*] ./ps-empire client\x1b[0m'

if $SOURCE_MESSAGE; then
  echo -e '\x1b[1;34m[*] source ~/.bashrc to enable nim \x1b[0m'
fi
