#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <time.h>

#include "crypt_blowfish.h"
#include "password.h"
#include "config.h"

extern int msgno;

static void
usage (char *arg)
{
    char *command = basename(arg);

    printf("Usage: %s -h <HASH>\n\n", command);
    printf("  -h, --hash=HASH password hashed\n");
    printf("  -V, --version   print version\n");
}

int
main(int argc, char **argv)
{
    char *hash = NULL;
    int cost = 0;
    char *algo = NULL;
    size_t len;

    int opt;
    const struct option long_options[] = {
        { "hash", 1, NULL, 'h' },
        { "verbose", 1, NULL, 'v' },
        { "quiet", 0, NULL, 'q' },
        { "version", 0, NULL, 'V' },
        { "help", 0, NULL, 'H' },
        { NULL, 0, NULL, 0 }
    };

    msgno = 0;

    while ((opt = getopt_long(argc, argv, "h:vVH",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                hash = optarg;
                break;
            case 'v':
                if (optarg) {
                    msgno = atoi(optarg);
                } else {
                    msgno += 1;
                }
                break;
            case 'q':
                msgno = -1;
                break;
            case 'V':
                printf("PHP Password Hashing version: %d.%d.%d\n",
                       PHP_PASSWORD_VERSION_MAJOR,
                       PHP_PASSWORD_VERSION_MINOR,
                       PHP_PASSWORD_VERSION_BUILD);
                return 0;
            case 'H':
            default:
                usage(argv[0]);
                return -1;
        }
    }

    if (password_get_info(hash, &algo, &cost) == 0) {
        printf("algorithm = %s\n", algo);
        printf("cost = %d\n", cost);
    }

    return 0;
}
