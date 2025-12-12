<div align="center">

![Empire](https://user-images.githubusercontent.com/20302208/70022749-1ad2b080-154a-11ea-9d8c-1b42632fd9f9.jpg)
[![Donate](https://img.shields.io/badge/Donate-Sponsor-blue?style=plastic&logo=github)](https://github.com/sponsors/BC-SECURITY)
[![Docs](https://img.shields.io/badge/Wiki-Docs-green?style=plastic&logo=wikipedia)](https://bc-security.gitbook.io/empire-wiki/)
[![Discord](https://img.shields.io/discord/716165691383873536?style=plastic&logo=discord)](https://discord.gg/P8PZPyf)
[![Blog](https://img.shields.io/badge/Blog-Read%20me-orange?style=plastic&logo=wordpress)](https://www.bc-security.org/blog)
[![Twitter URL](https://img.shields.io/twitter/follow/BCSecurity?style=plastic&logo=twitter)](https://twitter.com/BCSecurity)
[![Twitter URL](https://img.shields.io/twitter/follow/EmpireC2Project?style=plastic&logo=twitter)](https://twitter.com/EmpireC2Project)
[![YouTube URL](https://img.shields.io/youtube/channel/views/UCIV4xSntF1h1bvFt8SUfzZg?style=plastic&logo=youtube)](https://www.youtube.com/channel/UCIV4xSntF1h1bvFt8SUfzZg)
[![LinkedIn](https://img.shields.io/badge/Linkedin-blue?style=plastic&logo=linkedin&logoColor=#0A66C2)](https://www.linkedin.com/company/bc-security/)

</div>

# Empire
Empire is a post-exploitation and adversary emulation framework that is used to aid Red Teams and Penetration Testers. The Empire server is written in Python 3 and is modular to allow operator flexibility. Empire comes built-in with a client that can be used remotely to access the server. There is also a GUI available for remotely accessing the Empire server, [Starkiller](https://github.com/BC-SECURITY/Starkiller).

### Features
- Server/Client Architecture for Multiplayer Support
- Fully encrypted communications
- HTTP/S, Malleable HTTP, OneDrive, Dropbox, and PHP Listeners
- Massive library (400+) of supported tools in PowerShell, C#, & Python
- Donut Integration for shellcode generation
- Modular plugin interface for custom server features
- Flexible module interface for adding new tools
- Integrated obfuscation using [ConfuserEx 2](https://github.com/mkaring/ConfuserEx) & [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- In-memory .NET assembly execution
- Customizable Bypasses
- JA3/S and JARM Evasion
- MITRE ATT&CK Integration
- Integrated Roslyn compiler (Thanks to [Covenant](https://github.com/cobbr/Covenant))
- Docker, Kali, ParrotOS, Ubuntu 22.04/24.04, and Debian 11/12 Install Support

### Agents
- PowerShell
- Python 3
- C#
- IronPython 3
- Go

### Modules
- [Assembly Execution](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/code_execution/Invoke-Assembly.ps1)
- [BOF Execution](https://github.com/airbus-cert/Invoke-Bof)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [SharpSploit](https://github.com/cobbr/SharpSploit)
- [Certify](https://github.com/GhostPack/Certify)
- [ProcessInjection](https://github.com/3xpl01tc0d3r/ProcessInjection)
- And Many More

## Sponsors
<div align="center">

[<img src="https://github.com/user-attachments/assets/604fbb97-4641-4a15-a6ba-039f67694f15" width="200"/>](https://www.route4me.com//)


[<img src="https://github.com/user-attachments/assets/8685f8de-ad66-46d3-8751-8f2bdddc4ac1" width="100"/>](https://www.instagram.com/purpl3_cult/)
</div>

## Release Notes

Please see our [Releases](https://github.com/BC-SECURITY/Empire/releases) or [Changelog](/CHANGELOG.md) page for detailed release notes.

###  Quickstart
When cloning this repository, you will need to recurse submodules.
```sh
git clone --recursive https://github.com/BC-SECURITY/Empire.git
```

Check out the [Installation Page](https://bc-security.gitbook.io/empire-wiki/quickstart/installation) for install instructions.

Note: The `main` branch is a reflection of the latest changes and may not always be stable.
After cloning the repo, you can checkout the latest stable release by running the `setup/checkout-latest-tag.sh` script.
```bash
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/checkout-latest-tag.sh
./ps-empire install -y
```

If you are using the sponsors version of Empire, it will pull the sponsors version of Starkiller.
Because these are private repositories, you need to have ssh credentials configured for GitHub.
Instructions can be found [here](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh).

#### Server

```bash
# Start Server
./ps-empire server

# Help
./ps-empire server -h
```

Check out the [Empire Docs](https://bc-security.gitbook.io/empire-wiki/) for more instructions on installing and using with Empire.
For a complete list of changes, see the [changelog](./changelog).

## Starkiller
<div align="center"><img width="125" src="https://user-images.githubusercontent.com/20302208/208271792-91973457-2d6c-4080-8625-0f9eebed0a82.png"></div>

[Starkiller](https://github.com/BC-SECURITY/Starkiller) is a web application GUI for PowerShell Empire that interfaces remotely with Empire via its API.
Starkiller can be ran as a replacement for the Empire client or in a mixed environment with Starkiller and Empire clients.
As of 5.0, Starkiller is packaged in Empire as a git submodule and doesn't require any additional setup.

## Contribution Rules
See [Contributing](./.github/CONTRIBUTING.md)

## Contributors
A special thanks to the following contributors for their help with Empire:

[@harmj0y](https://twitter.com/harmj0y)
[@sixdub](https://twitter.com/sixdub)
[@enigma0x3](https://twitter.com/enigma0x3)
[@rvrsh3ll](https://twitter.com/424f424f)
[@killswitch_gui](https://twitter.com/killswitch_gui)
[@xorrior](https://twitter.com/xorrior)
[@Cx01N](https://twitter.com/Cx01N_)
[@Hubbl3](https://twitter.com/_Hubbl3)
[@Vinnybod](https://twitter.com/_vinnybod)

## Official Discord Channel
Join us in [our Discord](https://discord.gg/P8PZPyf) with any comments, questions, concerns, or problems!

<p align="center">
<a href="https://discord.gg/P8PZPyf">
<img src="https://discordapp.com/api/guilds/716165691383873536/widget.png?style=banner3"/>
</p>
