/*
 * sync - synchronize cached writes to persistent storage
 *
 * Kiseki OS coreutils - POSIX compliant
 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    sync();
    return 0;
}
