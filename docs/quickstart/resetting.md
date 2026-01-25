# Resetting

Empire provides two maintenance flags to help you return the system to a clean state between runs.

## Reset

Start fresh without historical data while keeping generated files and dependencies on disk intact.

* What it does:
  * Drops existing data and reinitializes the database schema. On the next start, Empire repopulates default values defined in your configuration.
* What it does not do:
  * Does not delete or modify your configuration files (for example, config.yaml).
  * Does not delete Starkiller or Empire-Compiler.

### Example

```bash
./ps-empire server --reset
```

## Clean

Completely resets Empire to a pristine state, removing config and all Starkiller and Empire-Compiler files.

* What it does:
  * Performs everything --reset does (drops data and reinitializes the database).
  * Deletes configuration files (for example, config.yaml)
  * Removes Starkiller and Empire-Compiler files.
* What it does not do:
  * Does not uninstall system-level prerequisites (for example, Python, Docker, or database servers).
  * Does not remove your source checkout itself if you’re running from a cloned repository.

### Example

```bash
./ps-empire server --clean
```
