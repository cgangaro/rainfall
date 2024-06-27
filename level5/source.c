#include <stdio.h>
#include <stdlib.h>

void o() {
	system("/bin/sh");
	_exit(1);
}

int n() {
    char buffer[520];
    fgets(buffer, 512, stdin);
    printf("%s", buffer);
    exit(1);
}

int main() {
    n();
    return 0;
}