#!/bin/bash

tmp_root=$(mktemp -d)
build_dir=$PWD

# "copy files" to new root
make install DESTDIR="${tmp_root}" >&2

# create update image
cd "$tmp_root"
find -L . | cpio -oc | gzip > "$build_dir/update.img"

# cleanup
rm -rf "$tmp_root"
