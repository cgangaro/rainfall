#include <stdio.h>
#include <stdlib.h>

void run() {
    char* message = "Good... Wait what?\n";
    fwrite(message, 19, 1, stdout);
    system("/bin/sh");
}

int main() {
    char buffer[64];

    gets(buffer);
    return 0;
}