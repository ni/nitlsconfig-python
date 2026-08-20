# Contributing to nitlsconfig-python

Contributions to nitlsconfig-python are welcome from all!

nitlsconfig-python is managed via [git](https://git-scm.com), with the canonical upstream
repository hosted on [GitHub](https://github.com/ni/nitlsconfig-python/).

nitlsconfig-python follows a pull-request model for development.  If you wish to
contribute, you will need to create a GitHub account, fork this project, push a
branch with your changes to your project, and then submit a pull request.

Please remember to sign off your commits (e.g., by using `git commit -s` if you
are using the command line client). This amends your git commit message with a line
of the form `Signed-off-by: Name Lastname <name.lastmail@emailaddress.com>`. Please
include all authors of any given commit into the commit message with a
`Signed-off-by` line. This indicates that you have read and signed the Developer
Certificate of Origin (see below) and are able to legally submit your code to
this repository.

See [GitHub's official documentation](https://help.github.com/articles/using-pull-requests/) for more details.

# Getting Started

To contribute to this project, it is recommended that you follow these steps:

1. Ensure you have poetry installed.
1. Fork the repository on GitHub.
1. Install `nitlsconfig-python` dependencies using `poetry install`.
1. Run the regression tests on your system (see Testing section). At this point, if any tests fail, do not begin development. Try to investigate these failures. If you're unable to do so, report an issue through our [GitHub issues page](https://github.com/ni/nitlsconfig-python/issues).
1. Write new tests that demonstrate your bug or feature. Ensure that these new tests fail.
1. Make your change.
1. Run all the regression tests again (including the tests you just added), and confirm that they all pass.
1. Run `poetry run nps lint` to check that the updated code follows NI's Python coding conventions. If this reports errors, first run `poetry run nps fix` in order to sort imports and format the code with Black, then manually fix any remaining errors.
1. Run `poetry run mypy` to statically type-check the updated code.
1. Send a GitHub Pull Request to the main repository's main branch. GitHub Pull Requests are the expected method of code collaboration on this project.

# Testing

## Simple development loop

```
# Create a new branch
git fetch
git switch --create users/{username}/{branch-purpose} origin/main

# Install the project dependencies
poetry install

# ✍ Make source changes

# Run the analyzers -- see files in .github/workflows for details
poetry run nps lint
poetry run mypy
poetry run bandit -c pyproject.toml -r src/nitlsconfig

# Apply safe fixes
poetry run nps fix

# Run the tests
poetry run pytest -v
```

# Publishing on PyPI

You can publish the nitlsconfig package by creating a GitHub release
in the nitlsconfig-python repo. Here are the steps to follow to publish the package:

1. From the main GitHub repo page, select "Create a new release".
2. On the "New Release" page, create a new tag using the "Select Tag" drop down. The tag must be the package version, matching the value found in pyproject.toml. Example: `1.0.0a1`.
3. Enter a title in the "Release title" field. The title should contain the package name and version in the format `nitlsconfig <package-version>`. For example: `nitlsconfig 1.0.0a1`.
4. Click "Generate release notes" and edit the release notes.
  - Delete entries for PRs that do not affect users, such as "chore(deps):" and "fix(deps):" PRs.
  - Consider grouping related entries.
  - Reformat entries to be more readable. For example, change "Blah blah by so-and-so in \#123" to "Blah blah (\#123)".
5. If this is a pre-release release, check the "Set as a pre-release" checkbox.
6. Click "Publish release".
7. Creating a release will start the publish workflow. You can track the progress of this workflow in the "Actions" page of the GitHub repo.
8. The workflow job that publishes a package to pypi requires code owner approval. This job will automatically send code owners a notification email, then it will wait for them to log in and approve the deployment.
9. After receiving code owner approval, the publish workflow will resume.
10. Once the publish workflow has finished, you should see your release on pypi.

# Developer Certificate of Origin (DCO)

   Developer's Certificate of Origin 1.1

   By making a contribution to this project, I certify that:

   (a) The contribution was created in whole or in part by me and I
       have the right to submit it under the open source license
       indicated in the file; or

   (b) The contribution is based upon previous work that, to the best
       of my knowledge, is covered under an appropriate open source
       license and I have the right under that license to submit that
       work with modifications, whether created in whole or in part
       by me, under the same open source license (unless I am
       permitted to submit under a different license), as indicated
       in the file; or

   (c) The contribution was provided directly to me by some other
       person who certified (a), (b) or (c) and I have not modified
       it.

   (d) I understand and agree that this project and the contribution
       are public and that a record of the contribution (including all
       personal information I submit with it, including my sign-off) is
       maintained indefinitely and may be redistributed consistent with
       this project or the open source license(s) involved.

(taken from [developercertificate.org](https://developercertificate.org/))

See [LICENSE](https://github.com/ni/nitlsconfig-python/blob/main/LICENSE)
for details about how nitlsconfig-python is licensed.
