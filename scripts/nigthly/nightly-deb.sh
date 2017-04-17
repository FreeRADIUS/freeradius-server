#!/bin/bash
# Author: Jorge Pereira <jpereiran@gmail.com>
# Date: Qui Jun 25 21:43:59 UTC 2015
###

repo_dist="${1:-/var/www/html/repo/freeradius-nightly/dists}"
build_dir="/tmp/freeradius-build-nigthly/testing"
git_url="https://github.com/FreeRADIUS/freeradius-server"

branches="v3.0.x v3.1.x "

day=$(date "+%Y%m%d")

if [ ! -d "$build_dir" ];then
   if ! git clone $git_url $build_dir; then
	echo "** ops! can't clone the repository... leaving"
	exit
   fi
fi

mkdir -p $repo_dist
command -p cd $build_dir

# building
for br in ${branches[*]}; do
    tag="nightly-$day"
    br_nightly="$tag-$br"
    repo_dir="$repo_dist/$day"
    build_log="$repo_dir/build.log"

    echo "[**] Generating the $br_nightly based on $br"

    (
    # reset
    git clean -fdx
    git checkout --

    # back
    git checkout $br
    git reset --hard 
    git branch -D $br_nightly 
    mkdir -p $repo_dir
    ) 1> /dev/null 2>&-

    # update
    git pull --rebase
    git checkout -b $br_nightly $br

    echo "(***) Building $br_nightly on $repo_dir"
    (
    # prepare
    git-dch --snapshot \
            --snapshot-number=$day \
            --verbose \
            -c \
            --auto \
            --ignore-branch \
            --debian-branch=$br_nightly \
            --id-length=2 \
            --git-author "Jorge Pereira <jpereiran@gmail.com>"
    
    # build
    export GIT_PBUILDER_AUTOCONF=no
    export WIKIMEDIA=yes
    git-buildpackage  \
                     --git-export-dir=$repo_dir \
                     --git-upstream-branch=$br_nightly \
                     --git-debian-branch=$br_nightly \
		     --git-no-sign-tags

    ) 1> $build_log 2>&1
    [ -f "$build_log" ] && gzip -f $build_log

    # remote build dir
    find $repo_dir -type d -name "freeradius-*${day}*" -exec rm -rf {} \; 1> /dev/null 2>&1

done

# generate debian Package.gz
deb_package="$repo_dist/Packages"
echo "(**) Generating *.deb index in $deb_package"
dpkg-scanpackages $repo_dist /dev/null | gzip -9c > $repo_dist/Packages.gz
mkdir -p $repo_dist/main/binary-amd64/
zcat $repo_dist/Packages.gz > $repo_dist/main/binary-amd64/Packages.bz2

echo "Done"

