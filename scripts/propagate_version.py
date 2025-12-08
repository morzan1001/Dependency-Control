import os
import re
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
        r'version = "[0-9]+\.[0-9]+\.[0-9]+"',
        f'version = "{new_version}"'
    )

    # 2. Update Helm Chart (Chart.yaml)
    # version: 0.1.0
    # appVersion: "0.1.0"
    chart_path = os.path.join(root_dir, 'helm', 'dependency-control', 'Chart.yaml')
    update_file(
        chart_path,
        r'^version: [0-9]+\.[0-9]+\.[0-9]+',
        f'version: {new_version}',
        flags=re.MULTILINE
    )
    update_file(
        chart_path,
        r'appVersion: "[0-9]+\.[0-9]+\.[0-9]+"',
        f'appVersion: "{new_version}"'
    )
    update_file(
        chart_path,
        r'appVersion: "[0-9]+\.[0-9]+\.[0-9]+"',
        f'appVersion: "{new_version}"'
    )

if __name__ == "__main__":
    main()
