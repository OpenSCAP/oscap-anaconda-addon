Name:           oscap-anaconda-addon
Version:        0.2
Release:        1%{?dist}
Summary:        Anaconda addon integrating OpenSCAP to the installation process

License:        GPLv2+
URL:            https://git.fedorahosted.org/cgit/oscap-anaconda-addon.git

# This is a Red Hat maintained package which is specific to
# our distribution.
#
# The source is thus available only from within this SRPM
# or via direct git checkout:
# git clone git://git.fedorahosted.org/oscap-anaconda-addon.git
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:	python2-devel
BuildRequires:  python-mock
BuildRequires:  python-nose
BuildRequires:  anaconda >= 19
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
%dir %{_datadir}/anaconda/addons/org_fedora_oscap/gui/spokes
%dir %{_datadir}/anaconda/addons/org_fedora_oscap/gui/categories
%{_datadir}/anaconda/addons/org_fedora_oscap/*.py*
%{_datadir}/anaconda/addons/org_fedora_oscap/ks/*.py*
%{_datadir}/anaconda/addons/org_fedora_oscap/gui/*.py*
%{_datadir}/anaconda/addons/org_fedora_oscap/gui/spokes/*.py*
%{_datadir}/anaconda/addons/org_fedora_oscap/gui/spokes/*.glade
%{_datadir}/anaconda/addons/org_fedora_oscap/gui/categories/*.py*

%doc COPYING ChangeLog README

%changelog
* Mon Oct 21 2013 Vratislav Podzimek <vpodzime@redhat.com> - 0.2-1
- Initial RPM for the oscap-anaconda-addon
