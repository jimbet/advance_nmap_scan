#!/bin/bash
# Sir Jimbet nmap_scanner

# Detect OS and distro
if [ "$(uname -s)" = "Linux" ]; then
    if [ -f /etc/debian_version ]; then
        # Debian-based (e.g., Ubuntu, Debian)
        PM_UPDATE="sudo apt-get update"
        PM_INSTALL="sudo apt-get install -y"
        PYTHON_PKGS="python3 python3-pip python3-devel proxychains4"
        DNS_PKG="dnsutils"
        TOR_PKGS="tor"
        START_TOR="sudo systemctl start tor"
        ENABLE_TOR="sudo systemctl enable tor"
    elif [ -f /etc/redhat-release ] || grep -q "ID.*=.*fedora\|rhel\|centos" /etc/os-release 2>/dev/null; then
        # Red Hat/Fedora-based
        PM_UPDATE="sudo dnf5 update --refresh"
        PM_INSTALL="sudo dnf5 install -y"
        PYTHON_PKGS="python3 python3-pip python3-devel proxychains-ng"
        DNS_PKG="bind-utils"
        TOR_PKGS="tor"
        START_TOR="sudo systemctl start tor"
        ENABLE_TOR="sudo systemctl enable tor"
    else
        echo "Unsupported Linux distribution detected."
        exit 1
    fi
elif [ "$(uname -s)" = "FreeBSD" ]; then
    # FreeBSD
    PM_UPDATE="sudo pkg update"
    PM_INSTALL="sudo pkg install"
    PYTHON_PKGS="python3 py39-pip"
    DNS_PKG="dnsutils"
    TOR_PKGS="tor"
    START_TOR="sudo service tor start"
    ENABLE_TOR="sudo sysrc tor_enable=YES"
else
    echo "Unsupported OS detected (only Linux or FreeBSD supported)."
    exit 1
fi

# Update system package lists
eval "$PM_UPDATE"

# Install Python3 and pip (if not already installed)
eval "$PM_INSTALL $PYTHON_PKGS"

# Install dnsutils equivalent
eval "$PM_INSTALL $DNS_PKG"

# Install Python requests library (and dependencies; note: original list may have typos like 'Mapping', 'utils', 'legacy-cgi' - verify packages)
pip3 install --upgrade requests chardet urllib3 Mapping utils legacy-cgi charset-normalizer dnspython pysocks colorama

# TOR for anonymity
eval "$PM_INSTALL $TOR_PKGS"
eval "$START_TOR"
eval "$ENABLE_TOR"

### If using Windows, you have to install GIT and Microsoft C++ Distribution Tool >14.x
### Download TOR - [https://www.torproject.org/download/tor/](https://www.torproject.org/download/tor/)
### Another requirement : 
### Open PowerShell as administrator by searching for it in the Start menu, right-clicking, and selecting "Run as administrator." 
### Run the command Set-ExecutionPolicy RemoteSigned -Scope CurrentUser and confirm with 'Y' to allow script execution. 
### Then, execute Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin" to download and install Scoop. 
### In PowerShell : scoop install proxychains
### In PowerShell : scoop install which
### Rename or copy original proxychains_win32_x64.exe into proxychains.exe
### Setting PATH temporarily by : (or you can set the permanent environment yourself)
### set PATH=%PATH%;~\scoop\apps\proxychains\current;~\scoop\shims

# Verify installation
echo "=== Verification ==="
python3 --version
python3 -c "import requests; print('requests version:', requests.__version__)"
echo "=== Installation Complete! ==="
