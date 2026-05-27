# Installing Bywaf

This page lists practical dependency blocks for installing, running, and
building Bywaf on common Linux systems.

Bywaf is a Python 3 application. It can run directly from a source checkout,
from a Python virtual environment, from a wheel, or from the release Debian/RPM
packages.

## Debian And Ubuntu

For source checkout development, install Python, venv support, pip, and the
runtime dependency:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-full python3-prompt-toolkit
```

On systems where `python3` is Python 3.14, the venv package may be versioned:

```bash
sudo apt install python3.14-venv
```

If you want `python` to mean `python3`:

```bash
sudo apt install python-is-python3
```

For the bundled network wrappers, install the external tools you intend to use.
`hostscanner` and `portscanner` need the `nmap` executable plus a supported
Python binding. On Debian/Ubuntu, use `python3-libnmap` when installing from
system packages:

```bash
sudo apt install nmap python3-libnmap nikto kismet
```

`eyewitness` packaging varies by distribution; install it from your distro or
the upstream project if you plan to use the `http/eyewitness` wrapper.

For Debian package builds:

```bash
sudo apt install debhelper dh-python pybuild-plugin-pyproject python3-all python3-setuptools python3-prompt-toolkit
```

## Fedora, RHEL, CentOS, Rocky, Alma

For source checkout development:

```bash
sudo dnf install python3 python3-pip python3-prompt-toolkit
```

For the bundled network wrappers, install the external tools you intend to use.
`hostscanner` and `portscanner` need the `nmap` executable plus a supported
Python binding. The RPM package recommends `python3-libnmap`; package names can
vary by distribution:

```bash
sudo dnf install nmap python3-libnmap nikto kismet
```

Package names for `eyewitness` vary; install it from your distribution or the
upstream project if needed.

For RPM package builds:

```bash
sudo dnf install python3 python3-build python3-installer python3-setuptools rpm-build
```

## Source Checkout With Venv

Clone and install Bywaf in editable mode:

```bash
git clone https://github.com/roeyk/Bywaf.git
cd Bywaf
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m bywaf --version
python -m bywaf
```

If your system does not provide `python`, use `python3` after activation:

```bash
python3 -m pip install -e .
python3 -m bywaf
```

If `python3 -m venv .venv` fails with `ensurepip is not available`, install the
distribution venv package first. On Debian/Ubuntu that is usually
`python3-venv`, or a versioned package such as `python3.14-venv`.

## Wheel Install

From a release artifact:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install bywaf-0.12.1-py3-none-any.whl
bywaf --version
bywaf
```

## Debian Package Install

From a release `.deb`:

```bash
sudo apt install ./bywaf_0.12.1-1_all.deb
bywaf --version
bywaf
```

The Debian package declares `python3-prompt-toolkit` as a runtime dependency
and recommends `nmap` plus `python3-libnmap`.

## RPM Package Install

From a release `.rpm`:

```bash
sudo dnf install ./bywaf-0.12.1-1.noarch.rpm
bywaf --version
bywaf
```

The RPM package requires `python3-prompt-toolkit` and recommends `nmap` plus
`python3-libnmap`.

## Optional Python Plugin Dependencies

The core package keeps optional plugin libraries out of the default install.
Install them only when you need those commandlets:

```bash
python -m pip install '.[plugins]'
```

This optional group includes Python libraries for DNS, LDAP, SMB, SSH, SNMP,
Shodan, and YARA integrations.

Nmap-backed commandlets also require the `nmap` executable plus one supported
Python binding. If your OS package manager does not provide `python3-libnmap`,
install one binding in the active virtual environment:

```bash
python -m pip install python-libnmap
```

Bywaf's nmap adapter currently recognizes bindings that import as `nmaplib`,
`nmap`, `nmapthon`, or `libnmap`; `python-libnmap` provides the `libnmap`
module.

Optional extras are also available for encrypted SQLCipher databases, signing,
and richer report export support:

```bash
python -m pip install '.[sqlcipher]'
python -m pip install '.[signing]'
python -m pip install '.[reporting]'
```

You can combine extras:

```bash
python -m pip install -e '.[plugins,signing,reporting]'
```

## Build Release Packages Locally

From a source checkout:

```bash
python -m pip install build installer twine
scripts/build_pip_package.sh
scripts/build_deb_package.sh
scripts/build_rpm_package.sh
```

To build all release packages:

```bash
scripts/build_release_packages.sh
```

The build scripts remove generated `build/` and `bywaf.egg-info/` metadata
before invoking Python packaging so stale source lists do not affect new
artifacts.

## Notes On System Python

Modern Debian/Ubuntu systems enforce PEP 668 and reject global `pip install`
into the system Python. Use a virtual environment, `pipx`, or the `.deb`
package instead of `pip install` against `/usr/bin/python3`.
