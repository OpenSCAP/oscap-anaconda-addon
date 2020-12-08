FROM fedora:rawhide

RUN dnf install -y \
  make \
  anaconda \
  openscap-python3 \
  python3-cpio \
  python3-pycurl \
  python3-pip \
  && dnf clean all

RUN pip install \
  pylint \
  pytest \
  mock

RUN mkdir /oscap-anaconda-addon
WORKDIR /oscap-anaconda-addon
