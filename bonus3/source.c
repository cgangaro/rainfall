#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    FILE *file;
    char buffer[65];
    int index;

    // Initialize the buffer with zeros
    memset(buffer, 0, 65);

    // Open the file in read mode
    file = fopen("input.txt", "r");
    if (file == NULL) {
        return -1;
    }

    // Check the number of arguments
    if (argc != 2) {
        return -1;
    }

    // Read 66 bytes from the file and store them in the buffer
    fread(buffer, 1, 66, file);
    buffer[65] = '\0';

    // Convert the second argument to an integer
    index = atoi(argv[1]);
    buffer[index] = '\0';

    // Read 65 bytes from the file and store them in buffer + 0x42 (66)
    fread(buffer + 66, 1, 65, file);

    // Close the file
    fclose(file);

    // Compare the contents of the buffer with the second argument
    if (strcmp(buffer, argv[1]) == 0) {
        // Execute the program /bin/sh with execl if the comparison is equal
        execl("/bin/sh", "/bin/sh", NULL);
    } else {
        // Print the contents of buffer + 0x42 (66) if the comparison is not equal
        puts(buffer + 66);
    }

    return 0;
}
