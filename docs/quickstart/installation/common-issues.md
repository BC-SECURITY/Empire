# Common Issues

## Issue

```
Current Python version (3.12.2) is not allowed by the project (>=3.13,<3.14).
Please change python executable via the "env use" command.
```

## Solution

```
sudo rm -rf .venv
poetry install
```

## Issue

```
[*] Updating goenv
fatal: not a git repository (or any of the parent directories): git
```

## Solution

Open a new terminal, the install script should have set `$GOENV_ROOT` in your bashrc or zshrc file.
