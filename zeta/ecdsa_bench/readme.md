## Benchmark of In-Kernel ECDSA Signing from User Space

This program uses the Linux API to access to in-kernel cryptographic
operations. This Go program makes direct syscalls to the kernel similarly
to the `keyctl` utility command.

To run an example:
    $ make example

To run a benchmark:
    $ make benchmark

After that, the output looks like:

```
BenchmarkECDSAKernel
BenchmarkECDSAKernel-16          283    4283867 ns/op
BenchmarkECDSAGo
BenchmarkECDSAGo-16             1412     908581 ns/op
```

The difference in time is expected as the program should wait for the
operating system to respond the syscall, and move memory between the kernel
space and the user space.

Known Issues:

- "failed to load the private key into the keyring: bad message"
  This means the parser is not loaded. To solve this issue run:

  ```sh
   sudo modprobe pkcs8_key_parser
  ```

  or compile the parser directly into the kernel (instead of as a module)
