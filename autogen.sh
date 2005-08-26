#! /bin/sh

aclocal  || exit 1
autoheader || exit 1
automake --force --add-missing --copy || exit 1
autoconf || exit 1

echo "Now run ./configure"

