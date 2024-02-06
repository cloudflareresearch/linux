all: compile

compile: rsa.go rsa_test.go
	go build -o example.exe
	go test -c -o bench.exe

example: example.exe
	./example.exe

benchmark: bench.exe
	./bench.exe -test.v -test.bench=.

clean:
	rm -f ./bench.exe ./example.exe