#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int num;
    char buffer[40];

    // Convert the first command-line argument to an integer
    num = atoi(argv[1]);

    // Check if the number is less than or equal to 9
    if (num <= 9) {
        // Copy the second command-line argument to the buffer
        memcpy(buffer, argv[2], num * 4);

        // Check if the num is equal to 0x574f4c46
        if (num == 0x574f4c46) {
            // Execute the "/bin/sh" shell
            execl("/bin/sh", "sh", NULL);
        }
    }

    return 0;
}
