all: compile

compile: rsa.go rsa_test.go
	go build -o example.exe
	go test -c -o bench.exe

load_parser:
	modprobe pkcs8_key_parser

example: rsa.go
	go build -o example.exe
	./example.exe

benchmark: rsa.go rsa_test.go
	go test -c -o bench.exe
	./bench.exe -test.v -test.bench=.

clean:
	rm -f ./bench.exe ./example.exe