set -e

name="$1"

if [ "$name" = "" ]; then
  echo "please provide a name as the first arg"
  exit
fi

# prepare path variables
workdir="$(dirname -- "$0")"
workdir="$(
  cd -- "$workdir"
  pwd
)"
kerneldir="$(dirname -- "$workdir")"

# build go code
pushd "$kerneldir/zeta/rsa_bench/"
go build -o rsa rsa.go
popd

pushd "$kerneldir/zeta/ecdsa_bench/"
go build -o ecdsa ecdsa.go
go test -o ecdsa.test -c ecdsa*.go
popd

# prepare home bin dir
pushd "$workdir/virtme-home/bin/"
rm -- *
ln -s "$kerneldir/zeta/rsa_bench/rsa"
ln -s "$kerneldir/zeta/ecdsa_bench/ecdsa"
ln -s "$kerneldir/zeta/ecdsa_bench/ecdsa.test"
popd

mkdir -p "WORK/$name"

# build and "deploy" kernel
make -j 16
/bin/cp arch/x86_64/boot/bzImage "WORK/$name"

# run vm
virtme-run \
  --kimg "WORK/$name/bzImage" \
  --rodir=/tmp/roothome=$(pwd)/WORK/virtme-home \
  --pwd
