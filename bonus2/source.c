#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int env_var = 0;

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

int main(int argc, char *argv[]) {

    if (argc != 3) {
        return 1;
    }

    char buffer[72] = {0};

    strncpy(buffer, argv[1], 0x28);

    strncpy(buffer + 0x28, argv[2], 0x20);
    const char* env_lang = getenv("LANG");

    if (env_lang != 0) {
        if (memcmp(env_lang, "fi", 2) == 0) {
            env_var = 1;
        } else if (memcmp(env_lang, "nl", 2) == 0) {
            env_var = 2;
        }
    }

    greetuser(buffer);
    return 0;
}


