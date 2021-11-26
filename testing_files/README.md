# Testing files

This directory contains files which can be used in unit tests or for manual testing.

## RPMs

- **customized_stig-1-1.noarch.rpm**
  - RPM file with a SCAP source data stream and a tailoring file
  - customized profile ID: xccdf_org.ssgproject.content_profile_stig_customized
  - files shipped in this RPM:
    - /usr/share/xml/scap/customized_stig/ssg-rhel8-ds.xml
    - /usr/share/xml/scap/customized_stig/tailoring-xccdf.xml
- **scap-security-guide.noarch.rpm**
  - a RPM package similar to a Fedora RPM package scap-security-guide
  - files shipped in this RPM:
    - /usr/share/doc/scap-security-guide/Contributors.md
    - /usr/share/doc/scap-security-guide/LICENSE
    - /usr/share/doc/scap-security-guide/README.md
    - /usr/share/man/man8/scap-security-guide.8.gz
    - /usr/share/scap-security-guide/ansible
    - /usr/share/scap-security-guide/ansible/ssg-fedora-role-default.yml
    - /usr/share/scap-security-guide/ansible/ssg-fedora-role-ospp.yml
    - /usr/share/scap-security-guide/ansible/ssg-fedora-role-pci-dss.yml
    - /usr/share/scap-security-guide/ansible/ssg-fedora-role-standard.yml
    - /usr/share/scap-security-guide/bash
    - /usr/share/scap-security-guide/bash/ssg-fedora-role-default.sh
    - /usr/share/scap-security-guide/bash/ssg-fedora-role-ospp.sh
    - /usr/share/scap-security-guide/bash/ssg-fedora-role-pci-dss.sh
    - /usr/share/scap-security-guide/bash/ssg-fedora-role-standard.sh
    - /usr/share/xml/scap/ssg/content
    - /usr/share/xml/scap/ssg/content/ssg-fedora-cpe-dictionary.xml
    - /usr/share/xml/scap/ssg/content/ssg-fedora-cpe-oval.xml
    - /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
    - /usr/share/xml/scap/ssg/content/ssg-fedora-ocil.xml
    - /usr/share/xml/scap/ssg/content/ssg-fedora-oval.xml
    - /usr/share/xml/scap/ssg/content/ssg-fedora-xccdf.xml
- **separate-scap-files-1-1.noarch.rpm**
  - contains SCAP content in form of separate components files (no data stream)
  - files shipped in this RPM:
    - /usr/share/xml/scap/separate-scap-files/ssg-rhel8-cpe-dictionary.xml
    - /usr/share/xml/scap/separate-scap-files/ssg-rhel8-cpe-oval.xml
    - /usr/share/xml/scap/separate-scap-files/ssg-rhel8-ocil.xml
    - /usr/share/xml/scap/separate-scap-files/ssg-rhel8-oval.xml
    - /usr/share/xml/scap/separate-scap-files/ssg-rhel8-xccdf.xml
- **single-ds-1-1.noarch.rpm**
  - contains a single SCAP source data stream which is a common RHEL 8 SCAP content
  - files shipped in this RPM:
    - /usr/share/xml/scap/single-ds/some_rhel8_content.xml
- **ssg-fedora-ds-tailoring-1-1.noarch.rpm**
  - RPM file containing a SCAP source data stream and a tailoring file
  - customized profile ID: xccdf_org.ssgproject.content_profile_ospp_customized2
  - files shipped in this RPM:
    - /usr/share/xml/scap/ssg-fedora-ds-tailoring/ssg-fedora-ds.xml
    - /usr/share/xml/scap/ssg-fedora-ds-tailoring/tailoring-xccdf.xml
- **xccdf-with-tailoring-1-1.noarch.rpm**
  - tailoring that modifies a plain XCCDF
  - customized profile ID: xccdf_org.ssgproject.content_profile_ospp_customized
  - files shipped in this RPM:
    - /usr/share/xml/scap/xccdf-with-tailoring/ssg-fedora-oval.xml
    - /usr/share/xml/scap/xccdf-with-tailoring/ssg-fedora-xccdf.xml
    - /usr/share/xml/scap/xccdf-with-tailoring/tailoring.xml

## ZIP files

- **ds-with-tailoring.zip**
  - this zip archive contains SCAP source data stream and a tailoring file that modifies one of the profiles
  - customized profile ID xccdf_org.ssgproject.content_profile_ospp_customized
  - contents of the archive:
    - ssg-fedora-ds.xml
    - tailoring.xml
- **separate-scap-files.zip**
  - contains SCAP content in form of separate components files (no data stream)
  - contents of the archive:
    - ssg-rhel8-cpe-dictionary.xml
    - ssg-rhel8-cpe-oval.xml
    - ssg-rhel8-ocil.xml
    - ssg-rhel8-oval.xml
    - ssg-rhel8-xccdf.xml
- **single-ds.zip**
  - contains a single SCAP source data stream which is a common RHEL 8 SCAP content
  - contents of the archive:
    - some_rhel8_content.xml
- **xccdf-with-tailoring.zip**
  - tailoring that modifies a plain XCCDF
  - customized profile ID: xccdf_org.ssgproject.content_profile_ospp_customized
  - contents of the archive:
    - ssg-fedora-oval.xml
    - ssg-fedora-xccdf.xml
    - tailoring.xml


## SCAP content files

- **tailoring.xml**
  - tailoring file for `xccdf.xml` (see below)
  - customized profiles:
    - xccdf_com.example_profile_my_profile2_tailored
    - xccdf_com.example_profile_my_profile_tailored
- **testing_ds.xml**
  - SCAP source data stream that contains 2 XCCDF benchmarks, great to test selection of a benchmark
- **testing_xccdf.xml**
  - very simple XCCDF file with a single rule which uses SCE
  - no profiles
- **xccdf.xml**
  - simple XCCDF with 2 profiles

## Kickstarts

- **testing_ks.cfg**
