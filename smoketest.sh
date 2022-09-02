#!/bin/bash
#
# This script downloads all the json dumps from GCP and make sure we
# can deserialize them as strongly typed values.
# 
# Requirements:
#
# - Google Cloud CLI installed: https://cloud.google.com/sdk/docs/install
# - fd: https://github.com/sharkdp/fd
#
#############################################################################


ensure_exists() {
    if ! command -v "$1" &>/dev/null
    then
        echo "$1 requirement not met"
        exit 1;
    fi
}

download() {
    buckets=$(gsutil ls gs://osv-vulnerabilities | grep -v ecosystems.txt)
    for subdir in $buckets
    do
        target=$(
            echo "$subdir" | \
            sed -e 's/gs.*osv-vulnerabilities//' \
                -e 's/\///g' \
                -e 's/:/_/'
        )
        mkdir -p "$(pwd)/testdata/$target"
        gsutil cp "${subdir}all.zip" "$(pwd)/testdata/$target"
    done
}

extract() {
    for zipfile in $(fd all.zip)
    do 
        target=$(dirname "$zipfile")
        unzip -d "$target" "$zipfile"
    done
}

build(){
    cargo run --example parse 2>/dev/null
}

find_bugs(){
    fd -e json \
        --exclude testdata/GSD \
        --exclude testdata/DWF \
        --exclude testdata/JavaScript \
        --full-path ./testdata \
        -x ./target/debug/examples/parse | grep -v pass
}

main(){
    ensure_exists gsutil
    ensure_exists fd
    mkdir -p testdata
    download
    extract
    build
    find_bugs
}

main
