all: compile

compile: rsa.go rsa_test.go
	go build -o rsa.exe rsa.go
	go test -c -o bench.exe rsa.go rsa_test.go

rsa: rsa.exe
	./rsa.exe

benchmark: bench.exe
	./bench.exe -test.v -test.bench=.

clean:
	rm -f ./bench.exe ./rsa.exe
