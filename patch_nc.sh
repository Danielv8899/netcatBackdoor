#!/bin/bash
sudo apt-get install --yes dpkg-dev
sudo cp /etc/apt/sources.list /etc/apt/sources.list~
sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
sudo apt-get update
sudo apt-get install --yes quilt
mkdir netcat
cd netcat
apt source netcat-openbsd
cd netcat-openbsd-*/
sudo apt-get install --yes $(dpkg-checkbuilddeps 2>&1 | sed -e 's/dpkg-checkbuilddeps:\serror:\sUnmet build dependencies: //g' -e  's/[\(][^)]*[\)] //g')
quilt import ~/nc.patch
quilt push
res=$?
if [ $res == 0 ]; then
	sudo dpkg-buildpackage
else
	echo "patch failed to apply, verify source is up to date"
fi