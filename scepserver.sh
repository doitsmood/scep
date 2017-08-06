#!/bin/bash    

# pkcs7 scep request envelope
REQUEST=$1

echo "$REQUEST"

# the temp directory used, within $DIR
WORK_DIR=`mktemp -d -t "scep"` 

# check if tmp dir was created
if [[ ! "$WORK_DIR" || ! -d "$WORK_DIR" ]]; then
  echo "Could not create temp dir"
  exit 1
fi

# deletes the temp directory
function cleanup {      
  rm -rf "$WORK_DIR"
  echo "Deleted temp working directory $WORK_DIR"
}

# register the cleanup function to be called on the EXIT signal
trap cleanup EXIT
