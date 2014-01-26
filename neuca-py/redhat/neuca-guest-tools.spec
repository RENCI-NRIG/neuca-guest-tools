%if ! (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}
%endif

Name:           neuca-guest-tools
Version:        1.4
Release:        1
Summary:        NEuca - the ExoGENI VM post-boot configuration utility

Group:          Applications/System
License:        MIT/GENI Public License License
URL:            https://code.renci.org/svn/networkedclouds/neuca-guest-tools/trunk/neuca-py
Source:         %{name}-%{version}.tgz
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: python2-devel
Requires: python-boto python-daemon python-ipaddr python-netaddr iscsi-initiator-utils
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig /sbin/service

%description
NEuca provides a set of utilities for performing post-boot configuration
for VMs within ExoGENI.

%prep
%setup -q

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{python_sitelib}
%{__python} setup.py install --skip-build --root %{buildroot}
install -p -D -m 755 redhat/neuca.init %{buildroot}/etc/rc.d/init.d/neuca
install -d -m 755 %{buildroot}/var/log/neuca

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/etc/rc.d/init.d/neuca
%{_bindir}/neuca*
%{python_sitelib}/neuca_guest_tools
%{python_sitelib}/*.egg-info
%dir /var/log/neuca

%post
/sbin/chkconfig --add neuca >/dev/null 2>&1 ||:

%preun
/sbin/chkconfig --del neuca >/dev/null 2>&1 ||:

%changelog
* Tue Dec 17 2013 Victor J. Orlikowski <vjo@duke.edu> - 1.4-1
- 1.4 Initial packaging for RPM-based distributions
