#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)
#define FIXTURE_EXPORT __declspec(dllexport)
#else
#define FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

#if defined(__GNUC__)
#define FIXTURE_NOINLINE __attribute__((noinline))
#else
#define FIXTURE_NOINLINE
#endif

FIXTURE_EXPORT FIXTURE_NOINLINE
int vulnerable_analyze(const char *command, const char *input) {
    char buffer[8];
    strcpy(buffer, input);
    chmod("binaryscan-vulnerable-fixture", 0777);
    return system(command);
}

int main(int argc, char **argv) {
    if (argc < 3) return 0;
    return vulnerable_analyze(argv[1], argv[2]);
}
