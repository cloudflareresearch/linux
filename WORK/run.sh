dmesg -w &

for i in $(seq 10); do
	./zeta/ecdsa_bench/ecdsa
done
