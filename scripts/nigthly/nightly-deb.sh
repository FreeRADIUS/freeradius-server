#!/bin/bash

day=$(date "+%Y%m%d")
repo_dist="$PWD/../repo/debian/freeradius/"
branches="v3.0.x v3.1.x"
branches="v3.1.x v3.0.x v2.x.x"
branches="v3.0.x"

#git clone https://github.com/FreeRADIUS/freeradius-server freeradius-server.git

#cd freeradius-server.git && {

for br in ${branches[*]}; do
    tag="nightly-$day-1"
    br_nigtly="$tag-$br"
    repo_dir="$repo_dist/nightly/$day/$br/"
    build_log="$repo_dir/build.log"

    echo "Processando $br_nigtly based on $br"

    rm -rf $repo_dir

    # reset
    git fetch --all
    git clean -fdx 1> /dev/null 2>&1
    git reset --hard 
    git checkout $br
    git pull 

    # create
    git branch -D $br_nigtly 1> /dev/null 2>&1
    git checkout -b $br_nigtly $br

    echo "Building $br/$br_nigtly on $repo_dir, saving the log in $build_log"
    
    (
    # build
    git-dch --snapshot \
            --snapshot-number=$day \
            --verbose \
            -c \
            --auto \
            --ignore-branch \
            --debian-branch=$br_nigtly \
            --id-length=2 \
            --git-author "Jorge Pereira <jpereiran@gmail.com>"
    
    export GIT_PBUILDER_AUTOCONF=no
    export DIST=trusty
    export WIKIMEDIA=yes
    git-buildpackage  \
                     --git-export-dir=$repo_dir \
                     --git-upstream-branch=$br_nigtly \
                     --git-debian-branch=$br_nigtly

    ) 1> $build_log 2>&1
    
    [ -f "$build_log" ] && gzip $build_log
    # [ -d "$repo_dir" ] && find $repo_dir -type d -iname "freeradius*" -exec rm -rf {} \;
done
#}

pbuilder --build --basetgz $repo_dist/lucid.tgz /tmp/build-area/packagename/
