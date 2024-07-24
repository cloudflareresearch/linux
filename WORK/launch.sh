set -e

name="$1"

if [ "$name" = "" ]; then
  echo "please provide a name as the first arg"
  exit
fi

mkdir -p "WORK/$name"

make -j 12
/bin/cp -f arch/x86_64/boot/bzImage "WORK/$name"
virtme-run --kimg "WORK/$name/bzImage" -a ignore_loglevel --pwd
