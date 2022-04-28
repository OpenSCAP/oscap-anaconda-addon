%if 0%{?rhel} == 8
%define anaconda_core_version 33
%endif
%if 0%{?rhel} == 9
%define anaconda_core_version 34
%endif
%if 0%{?fedora}
%define anaconda_core_version %{fedora}
%endif

Name:           oscap-anaconda-addon
Version:        2.0.0
Release:        0%{?dist}
Summary:        Anaconda addon integrating OpenSCAP to the installation process

License:        GPLv2+
URL:            https://github.com/OpenSCAP/oscap-anaconda-addon
Source0:        https://github.com/OpenSCAP/oscap-anaconda-addon/releases/download/r%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  make
BuildRequires:  gettext
BuildRequires:  python3-devel
BuildRequires:  python3-pycurl
BuildRequires:  openscap openscap-utils openscap-python3
BuildRequires:  anaconda-core >= %{anaconda_core_version}
Requires:       anaconda-core >= %{anaconda_core_version}
Requires:       python3-pycurl
Requires:       python3-kickstart
Requires:       openscap openscap-utils openscap-python3
Requires:       scap-security-guide

%description
This is an addon that integrates OpenSCAP utilities with the Anaconda installer
and allows installation of systems following restrictions given by a SCAP
content.

%prep
%autosetup -p1

%build

%check

%install
make install DESTDIR=%{buildroot} DEFAULT_INSTALL_OF_PO_FILES=no

%files
%{_datadir}/anaconda/addons/org_fedora_oscap
%{_datadir}/anaconda/dbus/confs/org.fedoraproject.Anaconda.Addons.OSCAP.conf
%{_datadir}/anaconda/dbus/services/org.fedoraproject.Anaconda.Addons.OSCAP.service
