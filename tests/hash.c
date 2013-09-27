#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cutter.h>
#include "../src/password.h"

extern int msgno;

void
test_success()
{
    char *hash = password_hash("password", BCRYPT_BLOWFISH,
                               NULL, BCRYPT_BLOWFISH_COST);
    cut_assert_not_null(hash);
    cut_assert_equal_int(60, strlen(hash));
    cut_assert_match("\\$2y\\$10\\$.*", hash);
    free(hash);
}

void
test_args_none()
{
    cut_assert_null(password_hash(NULL, NULL, NULL, 0));
}

void
test_args_only_password()
{
    msgno = -1;
    cut_assert_null(password_hash("password", NULL, NULL, 0));
}

void
test_args_only_algo()
{
    msgno = -1;
    cut_assert_null(password_hash(NULL, BCRYPT_BLOWFISH, NULL, 0));
}

void
test_args_only_salt()
{
    msgno = -1;
    cut_assert_null(password_hash(NULL, NULL, "salt", 0));
}

void
test_args_only_cost()
{
    msgno = -1;
    cut_assert_null(password_hash(NULL, NULL, NULL, BCRYPT_BLOWFISH_COST));
}

void
test_args_cost_lower()
{
    msgno = -1;
    cut_assert_null(password_hash("password", NULL, NULL, 1));
    cut_assert_null(password_hash("password", NULL, NULL, 2));
    cut_assert_null(password_hash("password", NULL, NULL, 3));
    cut_assert_null(password_hash("password", NULL, NULL, -10));
}

void
test_args_cost_upper()
{
    msgno = -1;
    cut_assert_null(password_hash("password", NULL, NULL, 32));
    cut_assert_null(password_hash("password", NULL, NULL, 33));
    cut_assert_null(password_hash("password", NULL, NULL, 50));
}

void
test_args_algo()
{
    char *hash = password_hash("password", "algorithm",
                               NULL, BCRYPT_BLOWFISH_COST);
    cut_assert_not_null(hash);
    cut_assert_equal_int(60, strlen(hash));
    cut_assert_match("\\$2y\\$10\\$.*", hash);
    free(hash);
}

void
test_args_salt_short()
{
    msgno = -1;
    cut_assert_null(password_hash("password", NULL,
                                  "a", BCRYPT_BLOWFISH_COST));
    cut_assert_null(password_hash("password", NULL,
                                  "abcdefghij", BCRYPT_BLOWFISH_COST));
    cut_assert_null(password_hash("password", NULL,
                                  "abcdefghijklmnopqrst", BCRYPT_BLOWFISH_COST));
    cut_assert_null(password_hash("password", NULL,
                                  "abcdefghijklmnopqrstu",
                                  BCRYPT_BLOWFISH_COST));
}

void
test_args_salt()
{
    char *hash = password_hash("password", NULL,
                               "abcdefghijklmnopqrstuv", BCRYPT_BLOWFISH_COST);
    cut_assert_not_null(hash);
    cut_assert_equal_int(60, strlen(hash));
    cut_assert_equal_string(
        "$2y$10$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK",
        hash);
    free(hash);
}

void
test_args_salt_binary()
{
    char *salt = NULL, *hash = NULL;
    int fd, n;
    size_t len, bytes = 0;

    len = BCRYPT_BLOWFISH_SALT_REQUIRED_LEN;

    salt = malloc(len + 1);
    memset(salt, 0, len + 1);

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        while (bytes < len) {
            n = read(fd, salt + bytes, len - bytes);
            if (n < 0) {
                break;
            }
            bytes += (size_t)n;
        }
        close(fd);
    }

    hash = password_hash("password", NULL, salt, BCRYPT_BLOWFISH_COST);
    cut_assert_not_null(hash);
    cut_assert_equal_int(60, strlen(hash));
    cut_assert_match("\\$2y\\$10\\$.*", hash);
    free(salt);
    free(hash);
}
