# Installation

We recommend using the installation script or the Docker images to run Empire.
Alternatively, you can install Empire via [Kali](https://www.kali.org/downloads/)'s package manager.

The following operating systems have been tested for Empire compatibility.

* 22.04 / 24.04
* Debian 11 / 12
* Kali Linux
* ParrotOS

As of Empire 6.0, Python 3.13 is the minimum Python version required.

## Github

Note: The `main` branch is a reflection of the latest changes and may not always be stable. After cloning the repo, you can checkout the latest stable release by running the `setup/checkout-latest-tag.sh` script.

```bash
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/checkout-latest-tag.sh
./ps-empire install -y
```

### Installation Script Options
When running the ps-empire installation script, you can use the following optional flags to customize the installation process:

- `-y`: Automatically answer 'Yes' to all prompts during installation. This is useful if you want to install all optional dependencies without being prompted for confirmation.
- `-f`: Force the installation as root. Normally, Empire does not recommend installing as the root user for security reasons. However, if you need to bypass this restriction, you can use this flag. **Note: Using this option is not recommended unless absolutely necessary.**
- `-h`: Displays the help text.
```
./ps-empire install -y -f
```

**Sponsors:**

```
git clone --recursive https://github.com/BC-SECURITY/Empire-Sponsors.git
cd Empire-Sponsors
./setup/checkout-latest-tag.sh sponsors
./ps-empire install -y
```

If you are using the sponsors version of Empire, it will pull the sponsors version of Starkiller.
Because these are private repositories, you need to have ssh credentials configured for GitHub. Instructions can be found [here](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh).

### CI: Private dependencies (bot user SSH key)

When building Docker images in CI that need to clone private repos (e.g., sponsors-only Starkiller and the private plugin registry), the most reliable setup is a single bot user with read access to all required repos.

1. Create a bot user and add it to an org team (e.g., `bots`) with read access to `Starkiller-Sponsors` and `Empire-Plugin-Registry-Sponsors`.
2. Generate an SSH keypair for the bot, add the public key to the bot’s GitHub account (Settings → SSH and GPG keys), and store the private key in CI secrets as `CI_SSH_KEY_BOT`.

## Kali

You can install Empire on Kali by running the following:
**Kali's version may be a few versions behind the latest release.**
**Note:** Kali requires you to run Empire with `sudo`.

```bash
sudo apt install powershell-empire
```


## Docker

If you want to run Empire using a pre-built docker container.

**Note**: For size savings on the image, it is not pre-built with the libraries needed for jar, dmg, and nim stagers. To add these to your image, run the `install.sh` script in the container and answer `y` to the prompts.

```bash
# Pull the latest image
docker pull bcsecurity/empire:latest

# Run the server with the rest api port open
docker run -it -p 1337:1337 bcsecurity/empire:latest

# To run the client against the already running server container
docker container ls
docker exec -it {container-id} ./ps-empire client

# with persistent storage
docker pull bcsecurity/empire:latest
docker create -v /empire --name data bcsecurity/empire:latest
docker run -it -p 1337:1337 --volumes-from data bcsecurity/empire:latest

# if you prefer to be dropped into bash instead of directly into empire
docker run -it -p 1337:1337 --volumes-from data --entrypoint /bin/bash bcsecurity/empire:latest
```

Note: These are example basic commands to get started with docker. Depending on the use case of the individual, one may need to reference the [Docker documentation](https://docs.docker.com).

All image versions can be found at: [https://hub.docker.com/r/bcsecurity/empire/](https://hub.docker.com/r/bcsecurity/empire/)

* The last commit from master will be deployed to the `latest` tag
* The last commit from the dev branch will be deployed to the `dev` tag
* All GitHub tagged releases will be deployed using their version numbers (v3.0.0, v3.1.0, etc)

## Community-Supported Operating Systems

At this time, we are choosing to only support Kali, ParrotOS, Debian 11/12, and Ubuntu 22.04/24.04 installations, however, we will accept pull requests that fix issues or provide installation scripts specific to other operating systems to this wiki.

## Common Issues


### Issue

```
Current Python version (3.12.2) is not allowed by the project (>=3.13,<3.14).
Please change python executable via the "env use" command.
```

#### Solution

```
sudo rm -rf .venv
poetry install
```


### Issue

```
[*] Updating goenv
fatal: not a git repository (or any of the parent directories): git
```

#### Solution

Open a new terminal, the install script should have set `$GOENV_ROOT` in your bashrc or zshrc file.
