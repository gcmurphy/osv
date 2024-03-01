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
    echo "Downloading vulnerability data.."
    buckets=$(gsutil ls gs://osv-vulnerabilities | grep -v ecosystems.txt)
    for subdir in $buckets
    do
        target=$(
            echo "$subdir" | \
            sed -e 's/gs.*osv-vulnerabilities//' \
                -e 's/\///g' \
                -e 's/:/_/' \
                -e 's/ /_/'
        )
        mkdir -p "$(pwd)/testdata/$target"
        gsutil cp "${subdir}all.zip" "$(pwd)/testdata/$target"
    done
}

extract() {
    echo "Extracting vulnerability data.."
    find ./testdata -type f -name all.zip | parallel --bar unzip -d {.} {}
}

build(){
    echo "Building parse example.."
    cargo run --features=client --example parse > /dev/null 2>&1
}

find_bugs(){
    echo "Searching for files that cannot be parsed.."
    find ./testdata -type f -name \*.json | parallel --bar ./target/debug/examples/parse {} | grep -v pass
}

main(){
    ensure_exists gsutil
    ensure_exists parallel
    mkdir -p testdata
    download
    extract
    build
    find_bugs
}

main
