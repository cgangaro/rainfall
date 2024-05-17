# Rainfall Level 0 Guide
This guide will walk you through the process of finding the password for the `level1` user.

## Procedure

### 1. Examine your environment
   
`id` : Shows user and group identities that you have.
```bash
uid=2020(level0) gid=2020(level0) groups=2020(level0),100(users)
```
`pwd` : Displays the current directory you are in.
```bash
/home/user/level0
```
`ls -la` : Lists files and their permissions in the current directory.
```bash
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
```

We can see that the `level0` binary has the `setuid` bit set, which means that it runs with the permissions of the owner of the file. In this case, the owner is `level1`. It executable by the `users` group, our current group.

We execute the binary to see what it does.
```bash
level0@RainFall:~$ ./level0 
Segmentation fault (core dumped)
```

### 2. Reverse engineering

We will use Ghidra to reverse engineer the binary.
You can find the analysis in [Ressources/ghidra_analyse_level0.c](Ressources/ghidra_analyse_level0.c), and the reconstructed C code in [source.c](source.c).

### 3. Analysis

We only find a main function that checks if the first argument is equal to 423.
If it is, it will execute a shell with the same group and user id as the current process.

```c
int main(int ac, char **av)
{
	int iVar1;
	char *execv_args[2];
	gid_t gid;
	uid_t uid;
	
	iVar1 = atoi(av[1]); // Convert the first argument to an integer
    if (iVar1 == 423) {
        execv_args[0] = strdup("/bin/sh"); // Duplicate the string, execv_args[0] == "/bin/sh"
        execv_args[1] = NULL; // Not found in the binary, but it is good practice to set the last element to NULL for execv arguments
        gid = getegid(); // Get the effective group id
		uid = geteuid(); // Get the effective user id
        setresgid(gid, gid, gid); // Set the real, effective, and saved group id
		setresuid(uid, uid, uid); // Set the real, effective, and saved user id
        execv("/bin/sh", execv_args); // Execute a shell with the arguments
    }
    else {
        fwrite("No !\n", 1, 5,stderr); // Write "No !" to stderr if the first argument is not 423
    }
	return (0);
}
```
`execv` takes the path to the program to execute and an array of arguments. The first argument is the path to the program (conventionally the name of the program), and the last argument must be NULL.

- The real UID/GID is the user/group that owns the process.
- The effective UID/GID is used to determine the permissions of the process.
- The saved UID/GID is used to save the effective UID/GID when the process switches to another user.

We saw previously that the binary has the `setuid` bit set, for the owner of the file: `level1`.
So if we run the binary with the argument `423`, it will execute a shell with the same user and group id as `level1`.

### 4. Exploitation

We will run the binary with the argument `423` to get a shell with the `level1` user id.
```bash
level0@RainFall:~$ ./level0 423
```
And we display the password for the `level1` user.
```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$ exit
```

Congratulations!
We can now connect to the `level1` user with this password.
```bash
level0@RainFall:~$ su level1
Password:
level1@RainFall:~$
```
