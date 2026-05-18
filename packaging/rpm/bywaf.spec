Name:           bywaf
Version:        0.9.0
Release:        1%{?dist}
Summary:        Highly-auditable Python 3 commandlet framework

License:        GPL-3.0-or-later
URL:            https://github.com/roeyk/Bywaf
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

%global python3_sitelib %(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"].replace("/usr/local", "/usr"))')

BuildRequires:  python3
BuildRequires:  python3-build
BuildRequires:  python3-installer
BuildRequires:  python3-setuptools

Requires:       python3
Requires:       python3-prompt-toolkit
Recommends:     nmap
Recommends:     python3-libnmap

%description
Bywaf is a commandlet framework for chaining plugin-driven workflows through an
auditable event and artifact model. It provides a REPL, runtime entities,
plugin completion metadata, SQLite-backed event storage, and bundled
commandlets for discovery, HTTP probing, runtime control, storage, artifacts,
and local filesystem inspection.

%prep
%autosetup

%build
python3 -m build --no-isolation --wheel

%install
python3 -m installer --destdir %{buildroot} --prefix /usr dist/*.whl

# Debian/Ubuntu's Python scheme installs prefix-based wheels under /usr/local.
# Normalize that into /usr so this RPM owns a normal system executable and
# import path on the local build host.
if [ -d "%{buildroot}/usr/local/bin" ]; then
    mkdir -p "%{buildroot}%{_bindir}"
    mv "%{buildroot}/usr/local/bin/"* "%{buildroot}%{_bindir}/"
fi
local_lib=$(find "%{buildroot}/usr/local/lib" -type d -name dist-packages -print -quit 2>/dev/null || true)
if [ -n "$local_lib" ]; then
    mkdir -p "%{buildroot}%{python3_sitelib}"
    cp -a "$local_lib/." "%{buildroot}%{python3_sitelib}/"
fi
rm -rf "%{buildroot}/usr/local"

%check
PYTHONPATH=%{buildroot}%{python3_sitelib} %{buildroot}%{_bindir}/bywaf --version

%files
%license LICENSE
%doc README.md USAGE.md PLUGIN_AUTHOR_GUIDE.md TERMINOLOGY.md EVENT_MODEL.md RUNTIME_MODEL.md CAPABILITY_MODEL.md CHANGELOG.md TODO.md GOALS.md
%{_bindir}/bywaf
%{python3_sitelib}/bywaf
%{python3_sitelib}/bywaf-*.dist-info

%changelog
* Mon May 18 2026 Roey Katz <roey.katz@gmail.com> - 0.9.0-1
- Initial RPM packaging scaffold.
