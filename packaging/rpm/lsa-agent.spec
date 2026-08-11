%global debug_package %{nil}

Name:           lsa-agent
Version:        %{lsa_version}
Release:        1%{?dist}
Summary:        Linux Security Auditor unified agent
License:        Proprietary
BuildArch:      noarch
Requires:       systemd
Requires:       ca-certificates

%description
Outbound-only, audit-only Linux security agent for the LSA platform. The agent
uses a one-time enrollment token and uploads locally signed evidence over HTTPS.

%prep

%build

%install
install -d %{buildroot}/opt/lsa-agent
tar -C %{lsa_source_root} \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' --exclude='*/tests' \
  -cf - agent scanner | tar -C %{buildroot}/opt/lsa-agent -xf -
install -m 0644 %{lsa_source_root}/agent/requirements.txt %{buildroot}/opt/lsa-agent/requirements.txt
python3 %{lsa_source_root}/agent/integrity.py build --root %{buildroot}/opt/lsa-agent --manifest %{buildroot}/opt/lsa-agent/integrity-manifest.json >/dev/null
install -D -m 0755 %{lsa_source_root}/agent/lsa-agent-enroll %{buildroot}/usr/sbin/lsa-agent-enroll
install -D -m 0644 %{lsa_source_root}/agent/lsa-agent.service %{buildroot}/usr/lib/systemd/system/lsa-agent.service

%post
systemctl daemon-reload >/dev/null 2>&1 || true
if [ -s /var/lib/lsa-agent/state.json ] && [ -s /etc/lsa-agent/config.json ]; then
  systemctl enable lsa-agent.service >/dev/null 2>&1 || true
  systemctl try-restart lsa-agent.service >/dev/null 2>&1 || true
fi

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now lsa-agent.service >/dev/null 2>&1 || true
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || true

%files
%dir /opt/lsa-agent
/opt/lsa-agent/agent
/opt/lsa-agent/scanner
/opt/lsa-agent/requirements.txt
/opt/lsa-agent/integrity-manifest.json
/usr/sbin/lsa-agent-enroll
/usr/lib/systemd/system/lsa-agent.service

%changelog
* Tue Aug 11 2026 Linux Security Auditor - 0.4.4-1
  - Pin the tenant platform identity and verify signed enrollment proofs.
* Wed Aug 05 2026 Linux Security Auditor - 0.4.3-1
- Keep Ansible runtime and temporary files inside the agent's writable state directory.

* Wed Aug 05 2026 Linux Security Auditor - 0.4.1-1
- Disable platform TLS certificate verification for managed-agent transport.

* Mon Aug 03 2026 Linux Security Auditor - 0.4.0-1
- Add runtime integrity verification and policy rollback protection.
