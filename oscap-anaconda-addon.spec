Name:           oscap-anaconda-addon
Version:        0.3
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
BuildRequires:  python-cpio
BuildRequires:  anaconda >= 19
Requires:       anaconda >= 19
Requires:       openscap openscap-utils openscap-python
Requires:       python-cpio

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
%{_datadir}/anaconda/addons/org_fedora_oscap

%doc COPYING ChangeLog README

%changelog
* Tue Dec 10 2013 Vratislav Podzimek <vpodzime@redhat.com> - 0.3-1
- Implement and use our own better function for joining paths
- The content entry should have focus if there is no content
- RPM is just a weird archive in the pre-installation phase
- Ignore RPM files as well
- Adapt tests to dir constants now ending with "/"
- CpioArchive cannot be created from a piped output
- Fix namespace definitions in the testing XCCDF file
- Prevent putting None into xccdf_session_is_sds
- Fix the __all__ variable in the common module
- Strip content dir prefix when setting xccdf/cpe paths
- Inform user we now support archive URLs as well
- Ignore various file types in the git repository
- Try to find content files in the fetched archive or RPM
- Run pylint -E as part of the test target
- Return list of extracted files/directories when extracting archive
- Do not try to search for empty file paths in archives
- Properly set the content type based on the URL's suffix
- Switch profiles on double-click
- Hook urlEntry's activate signal to fetchButton click
- Save the spoke's glade file with a new Glade
- The addon now requires the python-cpio package
- Use really_hide for the UI elements for datastream-id and xccdf-id
- Support for RPM content in the GUI spoke
- RPM content support for kickstart processing
- Add property for the raw post-installation content path
- Make content type case insensitive
- Rest of the code needed for RPM extraction
- Actually look for the file path in entry names
- Basic stuff needed for the RPM content support
- Run tests in paralel
- Specify files in a better way in spec

* Mon Oct 21 2013 Vratislav Podzimek <vpodzime@redhat.com> - 0.2-1
- Initial RPM for the oscap-anaconda-addon
