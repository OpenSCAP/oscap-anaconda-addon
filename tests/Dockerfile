FROM registry.fedoraproject.org/fedora:rawhide

RUN dnf update -y \
  ; dnf install -y \
  'dnf-command(download)' \
  make \
  anaconda \
  openscap \
  openscap-utils \
  openscap-python3 \
  scap-security-guide \
  python3-cpio \
  python3-pycurl \
  python3-pip \
  ; dnf clean all

RUN pip install \
  pylint \
  pytest \
  mock

RUN mkdir /oscap-anaconda-addon
WORKDIR /oscap-anaconda-addon
