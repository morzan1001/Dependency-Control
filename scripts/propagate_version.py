"""Propagate the value in VERSION across the project's version-stamped files.

Targets in this script are tied to the **app version** (backend +
frontend + helm chart + changelog header). The CI scanner script under
``ci-cd/scripts/scanner.sh`` carries its own independent
``SCRIPT_VERSION`` because pipelines pin against it directly — bumping
the app version must not silently change scanner behaviour. When the
scanner itself changes, edit the value in ``ci-cd/scripts/scanner.sh``
and re-run this script to publish a frozen copy under
``ci-cd/scripts/versions/scanner-X.Y.Z.sh`` (see step 6 below).
"""

import hashlib
import os
import re
import shutil
import sys


def read_version(version_file):
    with open(version_file, 'r') as f:
        return f.read().strip()


def update_file(file_path, pattern, replacement, flags=0):
    with open(file_path, 'r') as f:
        content = f.read()

    new_content = re.sub(pattern, replacement, content, flags=flags)

    if content != new_content:
        with open(file_path, 'w') as f:
            f.write(new_content)
        print(f"Updated {file_path}")
    else:
        print(f"No changes needed for {file_path}")


def freeze_scanner(root_dir):
    """Copy ``ci-cd/scripts/scanner.sh`` into ``versions/`` under its
    embedded ``SCRIPT_VERSION``.

    A frozen file is immutable: if the target already exists with
    different bytes, the script aborts loudly. The release process is
    then:
      1. Edit ``ci-cd/scripts/scanner.sh`` and bump its ``SCRIPT_VERSION``.
      2. Run ``scripts/propagate_version.py``.
      3. Commit both the latest pointer and the new frozen file together.
    """
    scanner_path = os.path.join(root_dir, 'ci-cd', 'scripts', 'scanner.sh')
    if not os.path.exists(scanner_path):
        print(f"scanner.sh not found at {scanner_path}; skipping freeze")
        return

    with open(scanner_path, 'rb') as f:
        scanner_bytes = f.read()
    match = re.search(rb'SCRIPT_VERSION="(\d+\.\d+\.\d+)"', scanner_bytes, flags=re.ASCII)
    if not match:
        print("scanner.sh has no SCRIPT_VERSION=X.Y.Z line; skipping freeze")
        return
    scanner_version = match.group(1).decode("ascii")

    versions_dir = os.path.join(root_dir, 'ci-cd', 'scripts', 'versions')
    os.makedirs(versions_dir, exist_ok=True)
    frozen_path = os.path.join(versions_dir, f'scanner-{scanner_version}.sh')

    if os.path.exists(frozen_path):
        with open(frozen_path, 'rb') as f:
            frozen_bytes = f.read()
        if frozen_bytes == scanner_bytes:
            print(f"No changes needed for {frozen_path}")
            return
        live_sha = hashlib.sha256(scanner_bytes).hexdigest()
        frozen_sha = hashlib.sha256(frozen_bytes).hexdigest()
        print(
            f"ERROR: scanner-{scanner_version}.sh already exists with different bytes.\n"
            f"  frozen: {frozen_sha}\n"
            f"  live:   {live_sha}\n"
            f"Released versions are immutable. Bump SCRIPT_VERSION in scanner.sh "
            f"and rerun.",
            file=sys.stderr,
        )
        sys.exit(1)

    shutil.copyfile(scanner_path, frozen_path)
    print(f"Froze {frozen_path}")


def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    version_file = os.path.join(root_dir, 'VERSION')

    if not os.path.exists(version_file):
        print("VERSION file not found")
        sys.exit(1)

    new_version = read_version(version_file)
    print(f"Propagating version: {new_version}")

    # 1. Update Backend (pyproject.toml)
    # version = "0.1.0"
    pyproject_path = os.path.join(root_dir, 'backend', 'pyproject.toml')
    update_file(
        pyproject_path,
        r'^version = "[^"]+"',
        f'version = "{new_version}"',
        flags=re.MULTILINE
    )

    # 2. Update Helm Chart (Chart.yaml)
    # version: 0.1.0
    # appVersion: "0.1.0"
    chart_path = os.path.join(root_dir, 'helm', 'dependency-control', 'Chart.yaml')
    update_file(
        chart_path,
        r'^version: .+',
        f'version: {new_version}',
        flags=re.MULTILINE
    )
    update_file(
        chart_path,
        r'appVersion: "[^"]+"',
        f'appVersion: "{new_version}"'
    )

    # 3. Update Backend (main.py)
    main_py_path = os.path.join(root_dir, 'backend', 'app', 'main.py')
    update_file(
        main_py_path,
        r'version\s*=\s*"[^"]+"',
        f'version="{new_version}"'
    )

    # 4. Update Frontend (package.json)
    package_json_path = os.path.join(root_dir, 'frontend', 'package.json')
    update_file(
        package_json_path,
        r'"version": "[^"]+"',
        f'"version": "{new_version}"'
    )

    # 5. Update CHANGELOG.md top-of-file release header.
    # The script only rewrites the first "# Release X.Y.Z" line so writing
    # actual changelog entries stays a manual step — we just keep the
    # header in sync with the propagated version.
    changelog_path = os.path.join(root_dir, 'CHANGELOG.md')
    if os.path.exists(changelog_path):
        update_file(
            changelog_path,
            r'\A# Release [^\n]+',
            f'# Release {new_version}',
        )
    else:
        print(f"CHANGELOG.md not found at {changelog_path}; skipping")

    # 6. Freeze the current scanner.sh under versions/ so pinned
    # pipelines can resolve ?v=<scanner-version> deterministically.
    # The scanner has its own SCRIPT_VERSION and is not bumped by this
    # script — see the module docstring.
    freeze_scanner(root_dir)


if __name__ == "__main__":
    main()
