%if ! (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}
%endif
%define use_systemd (0%{?fedora} && 0%{?fedora} >= 18) || (0%{?rhel} && 0%{?rhel} >= 7) || (0%{?suse_version} && 0%{?suse_version} >=1210)

Name:           neuca-guest-tools
Version:        1.6
Release:        1
Summary:        NEuca - the ExoGENI VM post-boot configuration utility

Group:          Applications/System
License:        MIT/GENI Public License License
URL:            https://code.renci.org/svn/networkedclouds/neuca-guest-tools/trunk/neuca-py
Source:         %{name}-%{version}.tgz
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root

# Common requirements
BuildRequires: python2-devel
Requires: python-boto python-daemon python-ipaddr python-netaddr iscsi-initiator-utils

%if %{use_systemd}
Requires: systemd
BuildRequires: systemd
%else
Requires:           initscripts
Requires(postun):   initscripts
Requires(post):     chkconfig
Requires(preun):    chkconfig
%endif

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
install -d -m 755 %{buildroot}/var/log/neuca
%if %{use_systemd}
%{__mkdir} -p %{buildroot}%{_unitdir}
%{__install} -m 644 neucad.service %{buildroot}%{_unitdir}/neucad.service
%else
%{__mkdir} -p %{buildroot}%{_initrddir}
%{__install} -m 755 redhat/neuca.init %{buildroot}%{_initrddir}/neuca
%endif

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%attr(755, root, root) %dir /etc/neuca
%attr(755, root, root) %dir /var/lib/neuca
%attr(755, root, root) %dir /var/lib/neuca/storage
%attr(755, root, root) %dir /var/log/neuca
%{_bindir}/neuca*
/etc/neuca/config
%{python_sitelib}/neuca_guest_tools
%{python_sitelib}/*.egg-info
%if %{use_systemd}
%{_unitdir}/neucad.service
%else
%{_initrddir}/neuca
%endif

%post
if [ "$1" = "1" ]; then
%if %use_systemd
    /usr/bin/systemctl enable neucad.service >/dev/null 2>&1 ||:
%else
    /sbin/chkconfig --add neuca >/dev/null 2>&1 ||:
%endif
fi

%preun
if [ "$1" = "0" ]; then
%if %use_systemd
    /usr/bin/systemctl --no-reload disable neucad.service >/dev/null 2>&1 || :
    /usr/bin/systemctl stop neucad.service >/dev/null 2>&1 ||:
%else
    /sbin/service neuca stop > /dev/null 2>&1
    /sbin/chkconfig --del neuca >/dev/null 2>&1 ||:
%endif
    /bin/rm -rf /var/log/neuca/*
    /bin/rm -rf /var/lib/neuca/storage/*
    for i in /var/lib/neuca/*; do
        if [ ! -d $i ]; then
            /bin/rm -f $i
        fi
    done
fi

%changelog
* Wed May 06 2015 Victor J. Orlikowski <vjo@duke.edu> - 1.6-1
- 1.6 Update to new revision

* Sat Nov 01 2014 Victor J. Orlikowski <vjo@duke.edu> - 1.5-1
- 1.5 Update to new revision

* Tue Dec 17 2013 Victor J. Orlikowski <vjo@duke.edu> - 1.4-1
- 1.4 Initial packaging for RPM-based distributions
