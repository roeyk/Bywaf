Name:           bywaf
%global bywaf_version %{!?bywaf_version:0.13.0}%{?bywaf_version}
Version:        %{bywaf_version}
Release:        1%{?dist}
Summary:        Highly-auditable Python 3 commandlet framework

License:        GPL-3.0-or-later
URL:            https://github.com/roeyk/Bywaf
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

%global python3_sitelib %(python3 -c 'import sys; print(f"/usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")')

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

# Some Python build hosts apply their own installation scheme even when
# installer receives --prefix /usr. Normalize those files into the RPM's
# expected Python site directory so %check and %files agree on one import path.
if [ -d "%{buildroot}/usr/local/bin" ]; then
    mkdir -p "%{buildroot}%{_bindir}"
    mv "%{buildroot}/usr/local/bin/"* "%{buildroot}%{_bindir}/"
fi
install_lib=$(find "%{buildroot}" -type d \( -name site-packages -o -name dist-packages \) -print -quit 2>/dev/null || true)
if [ -n "$install_lib" ] && [ "$install_lib" != "%{buildroot}%{python3_sitelib}" ]; then
    mkdir -p "%{buildroot}%{python3_sitelib}"
    cp -a "$install_lib/." "%{buildroot}%{python3_sitelib}/"
fi
rm -rf "%{buildroot}/usr/local" "%{buildroot}/opt"

%check
PYTHONPATH=%{buildroot}%{python3_sitelib} %{buildroot}%{_bindir}/bywaf --version

%files
%license LICENSE
%doc README.md USAGE.md CHANGELOG.md docs
%{_bindir}/bywaf
%{_bindir}/bywaf-architecture-metrics
%{_bindir}/bywaf-plugin-manifest
%{python3_sitelib}/bywaf
%{python3_sitelib}/bywaf-*.dist-info

%changelog
* Thu Jun 11 2026 Roey Katz <roey.katz@gmail.com> - 0.13.0-1
- Testing release with WafW00f wrapper integration, report-side passive
  analysis improvements, manifest dependency graph diagnostics, expanded
  plugin-authoring documentation and scaffolding, performance fixes, and
  plugin package-boundary cleanup.

* Wed May 27 2026 Roey Katz <roey.katz@gmail.com> - 0.12.2-1
- Patch release with documentation TOCs, documentation impact metrics, and
  refreshed system diagrams.

* Wed May 27 2026 Roey Katz <roey.katz@gmail.com> - 0.12.1-1
- Patch release with REPL/display/report/artifact/audit/control refactors,
  shared pager handling, and documentation/package refresh.

* Fri May 22 2026 Roey Katz <roey.katz@gmail.com> - 0.11.1-1
- Patch release with plugin checker AST inference, capability inventory,
  manifest generation improvements, readable plugin/commandlet listings,
  explicit secret variable assignment, and configurable variable-listing color.

* Fri May 22 2026 Roey Katz <roey.katz@gmail.com> - 0.11.0-1
- Testing release with provider-owned triggers, signed plugin manifests and
  catalogs, explicit trust bypasses for development, key-management policy
  documentation, and major internal package refactors.

* Tue May 19 2026 Roey Katz <roey.katz@gmail.com> - 0.10.0-1
- Feature-complete testing release with project workspaces, signed bundles,
  key management, plugin manifests, catalog signing checks, and expanded
  plugin/reporting support.

* Mon May 18 2026 Roey Katz <roey.katz@gmail.com> - 0.9.2-1
- Testing release with fixed pip, Debian, and RPM release packaging workflow.

* Mon May 18 2026 Roey Katz <roey.katz@gmail.com> - 0.9.1-1
- Testing release with finding workflows, completion regressions, and release packaging.

* Mon May 18 2026 Roey Katz <roey.katz@gmail.com> - 0.9.0-1
- Initial RPM packaging scaffold.
