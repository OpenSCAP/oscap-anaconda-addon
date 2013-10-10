Name:           oscap-anaconda-addon
Version:        0.1
Release:        1%{?dist}
Summary:        Anaconda addon integrating OpenSCAP to the installation process

License:        GPLv2+
URL:            https://git.fedorahosted.org/cgit/oscap-anaconda-addon.git
Source0:        https://git.fedorahosted.org/cgit/oscap-anaconda-addon.git/snapshot/r%{version}.tar.gz

BuildArch:      noarch
BuildRequires:	python2-devel
BuildRequires:  python-mock
Requires:       anaconda >= 19
Requires:       openscap openscap-utils openscap-python

%description
This is an addon that integrates OpenSCAP utilities with the Anaconda installer
and allows installation of systems following restrictions given by a SCAP
content.

%prep
%setup -q


%build

%check
make test


%install
make install DESTDIR=%{buildroot}

%files
%dir %{_datadir}/anaconda/addons/org_fedora_oscap/
%dir %{_datadir}/anaconda/addons/org_fedora_oscap/ks
%dir %{_datadir}/anaconda/addons/org_fedora_oscap/gui
%{_datadir}/anaconda/addons/org_fedora_oscap/*.py*
%{_datadir}/anaconda/addons/org_fedora_oscap/ks/*.py*
%{_datadir}/anaconda/addons/org_fedora_oscap/gui/*.py*
%doc COPYING ChangeLog README

%changelog
* Thu Oct 10 2013 Vratislav Podzimek <vpodzime@redhat.com> - 0.1-1
- Initial RPM for the oscap-anaconda-addon
