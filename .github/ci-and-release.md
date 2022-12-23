# CI Processes

## Build and Test
All pull requests will run the `Lint and Test` workflow.

* The workflow will run `black` and `isort` checks and then run `pytest` on Python 3.8, 3.9, and 3.10.
* If the pull request is coming from a `release/*` branch, it will build the docker image and run `pytest` on it
* If the pull request changes the `install.sh` script, it will run the install script on the supported OS and check for errors

## BC-SECURITY/Empire-Sponsors Sponsors & Kali Release Process
Sponsors and Kali releases go through the same release process. It is easier to manage Empire releases by not allowing them to be released at different times and have the version numbers diverge.
A side effect of this is its possible for a version bump to be empty (no changes) and still be released.

### 1. cherry-pick any changes from BC-SECURITY/Empire#main to BC-SECURITY/Empire-Sponsors#private-main
If you don't feel comfortable pushing to `private-main`, you can branch from `private-main` before cherry-picking and open a pull request to merge into `private-main`.

```bash
cd /tmp
git clone --recursive git@github.com:bc-security/empire-sponsors.git
cd empire-sponsors
git remote add upstream git@github.com:bc-security/empire.git
git fetch upstream
git checkout private-main

# cherry-pick all commits needed from main to private-main
git cherry-pick <commit-hash>

# If there's any conflicts, resolve them then:
git add -A
git cherry-pick --continue

# push
git push origin private-main
```

**Potential Enhancement:** Could add a GitHub workflow that you supply a commit hash and it will cherry-pick it into `private-main` and open a pull request.

### 2. Merge Empire-Sponsors/private-main -> (Empire-Sponsors/sponsors-main, Empire-Sponsors/kali-main)
Run the `Prerelease - Merge private-main` manual workflow. The branch that it runs on doesn't matter.
The workflow will merge `private-main` into `sponsors-main` and `kali-main`.

No pull requests will be opened, if there are issues that broke the code, they will manifest in CI when the release PR is open.

If this step fails, it is probably due to a merge conflict. In this case,
the merge conflicts need to be resolved, and its best to run this locally.

<details>
<summary>If `private-main` -> `kali-main` fails</summary>
<p>

```bash
cd /tmp
git clone --recursive git@github.com:bc-security/empire-sponsors.git
cd empire-sponsors
git checkout kali-main
git merge origin/private-main

# Fix the conflicts, then:
git add -A
git merge --continue
git push origin kali-main
```
</p>
</details>

<details>
<summary>If `private-main` -> `sponsors-main` fails</summary>
<p>

```bash
cd /tmp
git clone --recursive git@github.com:bc-security/empire-sponsors.git
cd empire-sponsors
git checkout sponsors-main
git merge origin/private-main

# Fix the conflicts, then:
git add -A
git merge --continue
git push origin sponsors-main
```
</p>
</details>

**Potential Enhancement:** I'm still considering if this step should open PRs instead of doing direct merges.

### 3. Start Private Release
Start a release by running the `Private - Create Release` manual workflow.
The branch that it runs on doesn't matter.
The workflow will then create a release branch, push it to the repo, and create a pull request into `private-main`.

* Updates `pyproject.toml` version
* Updates `empire.py` version
* Updates `CHANGELOG.md`

### 4. Manual Step - Merge private-main release PR
Once the first workflow runs, it will open one pull request from the `release/v{version}-private` branch to `private-main`.

Check the changelog on this branch, this will be the changelog that is used for the release notes.

Merge the pull request. **DO NOT SQUASH**

**Note**: If at this point there are additional changes for the release, merge them into the release branch, not
the `private-main` branch.

**Potential Enhancement:** Use a git diff to generate a list of changes as suggestions for the release notes.

### 5. Private - Tag and Release
Once the `release/` pull request is merged, the `Private - Tag Release` workflow will automatically run.
The workflow will create a tag and release on the `HEAD` of `private-main` using the release notes from `CHANGELOG.md` for the body of the release.

### 6. Start Sponsor/Kali Release
Start the release by running the `Sponsors & Kali - Create Release` manual workflow.
If starkiller needs to be updated, provide a `starkillerVersion` input. The value provided should be a git tag minus the `-kali` or `-sponsors` suffix.

This will first attempt to merge the `private-main` branch into `sponsors-main` and `kali-main` with the new release changes. Most likely, if there is a merge conflict here it is caused by `CHANGELOG.md` and should be minor. If that occurs, the merge conflict can be resolved in the pull request via the GitHub editor, or locally. 

If a Starkiller tag was provided, it will update the Starkiller submodule and the changelog accordingly. It does this on the `sponsors-main` and `kali-main` release branches separately.

A release PR will then be opened for each branch and the test suite will run.


#### 7. Manual Step - Merge sponsor/kali release PRs
Once the workflow runs, it will open two pull requests from the `release/v{version}-sponsors` and `release/v{version}-kali` branches to `sponsors-main` and `kali-main` respectively.

Check the changelog on these branches, this will be the changelog that is used for the release notes.

If there are sponsor/kali specific changelog entries that need to be added, add them to the `CHANGELOG.md` file on the release branch.

Merge the pull requests. **DO NOT SQUASH**

**Note**: If at this point there are additional changes for the release, merge them into the release branch, not
the `sponsors-main` branch or `kali-main` branch.

**Potential Enhancement** We could add automation that copies the `unreleased` section from the target branch to the version section in the `head` branch.

### 7. Tag and Release
Once the pull requests are merged, the `Sponsors - Tag Release` and `Kali - Tag Release` workflows will automatically run.
The workflows will create a tag and release on the `HEAD` of `sponsors-main` and `kali-main`, using the release notes from `CHANGELOG.md` for the body of the release.

### Setup
Requires a secret in the repo `RELEASE_TOKEN` that has `repo` and `workflow` access.

## BC-SECURITY/Empire Public Release Process
### 1. Start Release
Start a release by running the `Public - Create Release Branch` manual workflow. It doesn't matter which branch it runs on.
For the workflow input, provide the tag name that you want to release. If starkiller needs to be updated, provide a `starkillerVersion` input. The value provided should be a git tag.

The workflow will then checkout the chosen tag from the `sponsors` repo, create a release branch, push it to the public repo, and create a pull request into `main`.

The chosen tag should end in `-private`

### 2. Manual Steps - Merge release PR
Once the first workflow runs, it will open one pull request from the `release/v{version}` branch to `main`.

Check the changelog on this branch, this will be the changelog that is used for the release notes.

Merge the pull request. **DO NOT SQUASH**

**Note**: If at this point there are additional changes for the release, merge them into the release branch, not
the `main` branch. This will ensure the change ends up in the release properly.

### 3. Tag Release
Once the pull request is merged, the `Public - Tag Release` workflow will automatically run.
The workflow will create a tag and release on the `HEAD` of `main`, using the release notes from `CHANGELOG.md` for the body of the release.

The workflow will detect the last released tag, and use the release notes from the `CHANGELOG.md` between the last release and the current release.

### Docker Builds
The `Docker Image CI` workflow will build the docker image for the release. Pushes to `main` will update the `latest` tag.
Tagged releases will push to the corresponding tag in DockerHub.

### Setup
Requires secrets in the repo `DOCKER_USERNAME` and `DOCKER_PASSWORD` as well as `RELEASE_TOKEN` that has `repo` and `workflow` access.

## More Information
TODO: Link to CI/CD blog post once it is written.

## Contributing
To update the workflows if you don't have access to the `Empire-Sponsors` repo:
Merge to `main` in `Empire`, then we can cherry-pick the changes into `private-main`.

To update the workflows if you have access to the `Empire-Sponsors` repo:
Merge to `private-main` in `Empire-Sponsors`. It will automatically merge to `sponsors-main` and `kali-main` when the prerelease workflow runs. It will merge to `Empire#main` when the public release workflow runs.
