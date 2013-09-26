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

    printf("Usage: %s -p <PASSWORD>"
           " [-a <ALGORITHM>] [-s <SALT>] [-c <COST>]\n\n", command);
    printf("  -p, --password=PASSWORD   users's password\n");
    printf("  -a, --algorithm=ALGORITHM"
           " hashing algorithm (no used) [DEFAULT: %s]\n",
           BCRYPT_BLOWFISH);
    printf("  -s, --salt=SALT          "
           " salt to use when hashing the password\n");
    printf("  -c, --cost=COST          "
           " cost that should be used [DEFAULT: %d]\n",
           BCRYPT_BLOWFISH_COST);
    printf("  -V, --version             print version\n");
}

int
main(int argc, char **argv)
{
    char *password = NULL, *salt = NULL;
    char *hash = NULL;
    char *algo = BCRYPT_BLOWFISH;
    int cost = BCRYPT_BLOWFISH_COST;

    int opt;
    const struct option long_options[] = {
        { "password", 1, NULL, 'p' },
        { "algorithm", 1, NULL, 'a' },
        { "salt", 1, NULL, 's' },
        { "cost", 1, NULL, 'c' },
        { "verbose", 1, NULL, 'v' },
        { "quiet", 0, NULL, 'q' },
        { "version", 0, NULL, 'V' },
        { "help", 0, NULL, 'H' },
        { NULL, 0, NULL, 0 }
    };

    msgno = 0;

    while ((opt = getopt_long(argc, argv, "p:a:s:c:vqVH",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                password = optarg;
                break;
            case 'a':
                break;
            case 's':
                salt = optarg;
                break;
            case 'c':
                cost = atoi(optarg);
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

    hash = password_hash(password, algo, salt, cost);
    if (!hash) {
        return -1;
    }

    printf("%s\n", hash);

    free(hash);

    return 0;
}
