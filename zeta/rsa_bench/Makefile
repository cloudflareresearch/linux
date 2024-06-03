all: compile

compile: rsa.go rsa_test.go
	go build -o rsa.exe rsa.go
	go test -c -o bench.exe rsa.go rsa_test.go


rsa: rsa.exe
	./rsa.exe

load_parser:
	modprobe pkcs8_key_parser

benchmark: rsa.go rsa_test.go
	./bench.exe -test.v -test.bench=.

clean:
	rm -f ./bench.exe ./rsa.exe
