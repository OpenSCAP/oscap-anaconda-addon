%global _default_patch_flags --no-backup-if-mismatch

Name:           oscap-anaconda-addon
Version:        0.9
Release:        1%{?dist}
Summary:        Anaconda addon integrating OpenSCAP to the installation process

License:        GPLv2+
URL:            https://www.open-scap.org/tools/oscap-anaconda-addon/

# This is a Red Hat maintained package which is specific to
# our distribution.
#
# The source is thus available only from within this SRPM
# or via direct git checkout:
# git clone https://github.com/OpenSCAP/oscap-anaconda-addon.git
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  gettext
BuildRequires:	python2-devel
#BuildRequires:  python-mock
#BuildRequires:  python-nose
#BuildRequires:  python-cpio
BuildRequires:  anaconda-core >= 21.48.22.99
Requires:       anaconda-core >= 21.48.22.99
Requires:       openscap openscap-utils openscap-python
Requires:       python-cpio
Requires:       scap-security-guide

%description
This is an addon that integrates OpenSCAP utilities with the Anaconda installer
and allows installation of systems following restrictions given by a SCAP
content.

%prep
%setup -q -n %{name}-%{version}

%build

%check
make unittest


%install
make install DESTDIR=%{buildroot}

%files
%{_datadir}/anaconda/addons/org_fedora_oscap

%doc COPYING ChangeLog README.md

%changelog
* Mon Jun 11 2018 Watson Yuuma Sato <wsato@redhat.com> - 0.9-1
- Rebase to the upstream version 0.9
- Drop patch that fixed selection of RHEL Alternate Architecture datastream
  Resolves: rhbz#1564903
- Update project URL
  Resolves: rhbz#1502379

* Tue Feb 06 2018 Watson Yuuma Sato <wsato@redhat.com> - 0.8-4
- Define translation domain of oscap-anaconda-addon
  Resolves: rhbz#1540302

* Tue Dec 12 2017 Watson Yuuma Sato <wsato@redhat.com> - 0.8-3
- Return empty string when there is no tailoring file
  Resolves: rhbz#1520276

* Mon Dec 11 2017 Watson Sato <wsato@redhat.com> - 0.8-2
- Add japanese translation
- Update other translations
  Resolves: rhbz#1481190
- Fix selection of RHEL datastream
  Resolves: rhbz#1520358

* Mon Nov 27 2017 Watson Sato <wsato@redhat.com> - 0.8-1
- Rebase to the upstream version 0.8
  Related: rhbz#1472419

* Tue May 30 2017 Watson Sato <wsato@redhat.com> - 0.7-15
- Add japanese translation
- Update other translations
  Resolves: rhbz#1383181

* Thu Apr 20 2017 Raphael Sanchez Prudencio <rsprudencio@redhat.com> - 0.7-14
- Fixed gtk warning messages when anaconda is starting.
  Resolves: rhbz#1437106

* Tue Mar 28 2017 Martin Preisler <mpreisle@redhat.com> - 0.7-13
- Avoid long delay before a GeoIP related timeout in case internet is not available
  Resolves: rhbz#1379479

* Tue Sep 13 2016 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-12
- Properly handle tailoring files for datastreams
  Resolves: rhbz#1364929

* Thu Aug 25 2016 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-11
- Don't require blank stderr when running the oscap tool
  Resolves: rhbz#1360765
- Beware of the invalid profiles
  Resolves: rhbz#1365130
- Properly set the seen property for root passwords
  Resolves: rhbz#1357603

* Thu Jun 30 2016 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-10
- Clear spoke's info before setting an error
  Resolves: rhbz#1349446

* Wed Jun  1 2016 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-9
- Use the System hub category provided by Anaconda
  Resolves: rhbz#1269211
- Wait for Anaconda to settle before evaluation
  Resolves: rhbz#1265552
- Make the changes overview scrollable and smaller
  Related: rhbz#1263582
- Make the list of profiles scrollable
  Resolves: rhbz#1263582
- Do not try to create a single file multiple times
  Related: rhbz#1263315
- Avoid crashes on extraction errors
  Resolves: rhbz#1263315
- Disable GPG checks when installing content to the system
  Resolves: rhbz#1263216
- Allow fixing root password in graphical installations
  Resolves: rhbz#1265116
- Enforce the minimal root password length
  Resolves: rhbz#1238281
- Just report misconfiguration instead of crashing in text mode
  Resolves: rhbz#1263207
- Do not verify SSL if inst.noverifyssl was given
  Resolves: rhbz#1263257
- Also catch data_fetch.DataFetchError when trying to get content
  Resolves: rhbz#1263239
- Use new method signature with payload class
  Related: rhbz#1288636

* Wed Sep 16 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-8
- Do not remove the root password behind user's back
  Resolves: rhbz#1263254

* Mon Sep 7 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-7
- Completely skip the execute() part if no profile is selected
  Resolves: rhbz#1254973

* Mon Aug 24 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-6
- Specify the name of the help content file
  Resolves: rhbz#1254884
- Skip files unrecognized by the 'oscap info' command
  Resolves: rhbz#1255075
- Only allow DS and XCCDF ID selection if it makes sense
  Resolves: rhbz#1254876

* Tue Aug 4 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-5
- Make sure DS and XCCDF ID lists are correctly refreshed
  Resolves: rhbz#1240946
- Make sure the DS and XCCDF ID combo boxes are visible for DS content
  Resolves: rhbz#1249951
- Try to load the OSCAP session early for DS content
  Resolves: rhbz#1247654
- Test preinst_content_path before raw_preinst_content_path
  Resolves: rhbz#1249937
- Clear any error if switching to the dry-run mode
  Related: rhbz#1247677
- Do not continue with and invalid profile ID
  Resolves: rhbz#1247677
- Cover all potential places with a non-main thread changing Gtk stuff
  Resolves: rhbz#1240967

* Thu Jul 23 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-4
- Better handle and report erroneous states
  Resolves: rhbz#1241064
- Make sure (some more) GUI actions run in the main thread
  Resolves: rhbz#1240967
- Beware of RPM->cpio entries' paths having absolute paths
  Related: rhbz#1241064
- Only output the kickstart section with content and profile set
  Resolves: rhbz#1241395
- Just report integrity check failure instead of traceback
  Resolves: rhbz#1240710
- Properly react on download/loading issues in text+kickstart mode
  Related: rhbz#1240710
- Fetch and process the content even if GUI doesn't take care of it
  Resolves: rhbz#1240625

* Tue Jul 7 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-3
- Do not output redundant/invalid fields for the SSG content (vpodzime)
  Resolves: rhbz#1240285
- Better handle unsupported URL types (vpodzime)
  Resolves: rhbz#1232631
- React better on network issues (vpodzime)
  Resolves: rhbz#1236657
- Improve the description of the default profile (vpodzime)
  Resolves: rhbz#1238080
- Use the openscap-scanner package instead of openscap-utils (vpodzime)
  Resolves: rhbz#1240249
- Better handle the case with no profile selected (vpodzime)
  Resolves: rhbz#1235750
- Add newline and one blank line after the %%addon section (vpodzime)
  Resolves: rhbz#1238267
- Word-wrap profile descriptions (vpodzime)
  Resolves: rhbz#1236644

* Wed Jun 17 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-2
- Add gettext to BuildRequires (vpodzime)
  Related: rhbz#1204640

* Tue Jun 16 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.7-1
- Rebase to the upstream version 0.7
  Related: rhbz#1204640

* Tue Apr 28 2015 Vratislav Podzimek <vpodzime@redhat.com> - 0.6-1
- Rebase to the upstream version 0.6
  Resolves: rhbz#1204640

* Mon Aug 04 2014 Vratislav Podzimek <vpodzime@redhat.com> - 0.4-3
- Don't distribute backup files
  Resolves: rhbz#1065906
* Wed Jan 15 2014 Vratislav Podizmek <vpodzime@redhat.com> - 0.4-2
- Skip running tests on RHEL builds
  Related: rhbz#1035662
* Tue Jan 14 2014 Vratislav Podzimek <vpodzime@redhat.com> - 0.4-1
- Beware of running Gtk actions from a non-main thread
- Fix path to the tailoring file when getting rules
- A git hook for running tests when pushing
- Inform user if no profile is selected
- Visually mark the selected profile
- Better UX with content URL entry and progress label
- React on invalid content properly (#1032846)
- Stop spinner when data fetching is finished
- Make the data fetching thread non-fatal (#1049989)
- Exit code 2 from the oscap tool is not an error for us (#1050913)
- Be ready to work with archives/RPMs containing data streams
- Add unit tests for the keep_type_map function
- Add support for namedtuples to keep_type_map
- Add target for running pylint check
- Add target for running just unittests
- On the way to tailoring
- Tests for kickstart XCCDF tailoring handling
- Kickstart support for XCCDF tailoring
- Check session validity also when using XCCDF benchmark

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
