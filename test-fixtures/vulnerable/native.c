#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

__attribute__((noinline))
static int analyze(const char *command, const char *input) {
    char buffer[8];
    strcpy(buffer, input);
    chmod("/tmp/binaryscan-vulnerable-fixture", 0777);
    return system(command);
}

int main(int argc, char **argv) {
    if (argc < 3) return 0;
    return analyze(argv[1], argv[2]);
}
