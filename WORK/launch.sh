set -e

name="$1"

if [ "$name" = "" ]; then
  echo "please provide a name as the first arg"
  exit
fi

mkdir -p "WORK/$name"

# using clang because that's what the clangd intros said i must do
make CC=clang -j 12
/bin/cp arch/x86_64/boot/bzImage "WORK/$name"
virtme-run \
  --kimg "WORK/$name/bzImage" \
  -a ignore_loglevel \
  --rodir=/tmp/roothome=$(pwd)/WORK/virtme-home \
  --pwd
