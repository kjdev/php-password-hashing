#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include "crypt_blowfish.h"
#include "password.h"

int msgno = 0;

#define msg_error(_prog, ...) \
    if (msgno >= 0) fprintf(stderr, "password_" # _prog ": "__VA_ARGS__)
#define msg_verbose(_prog, ...) \
    if (msgno > 0) msg_error(_prog, __VA_ARGS__)
#define msg_verbose_ex(_prog, _level, ...) \
    if (msgno >= _level) msg_error(_prog, __VA_ARGS__)

static int
is_alphabet(const char *str, const size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (!(isalnum(str[i]) || str[i] == '.' || str[i] == '/')) {
            return -1;
        }
    }
    return 0;
}

static int
to_base64(char *str, size_t str_len, const size_t out_len)
{
    char *b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *buffer;
    size_t i;
    int n = 0, x = 0, l = 0;

    buffer = (char *)malloc(((str_len * 4 / 3 + 3) & ~0x03) + 1);
    if (!buffer) {
        msg_error(hash, "memory allocate\n");
        return -1;
    }

    for (i = 0; i < str_len; i++) {
        x = x << 8 | str[i];
        for (l += 8; l >= 6; l -= 6) {
            buffer[n++] = b[(x >> (l - 6)) & 0x3f];
        }
    }

    if (l > 0) {
        x <<= 6 - l;
        buffer[n++] = b[x & 0x3f];
    }

    for (; n % 4;) {
        buffer[n++] = '=';
    }

    if ((size_t)n < out_len) {
        free(buffer);
        return -1;
    }

    for (i = 0; i < out_len; i++) {
        if (buffer[i] == '+') {
            str[i] = '.';
        } else if (buffer[i] == '=') {
            free(buffer);
            return -1;
        } else {
            str[i] = buffer[i];
        }
    }

    free(buffer);

    return i;
}

static char *
make_salt(size_t len)
{
    char *buffer;
    int ret, fd, n;
    size_t i, length;
    size_t bytes = 0;

    if (len > (INT_MAX / 3)) {
        msg_error(hash, "length is too large to safely generate\n");
        return NULL;
    }

    buffer = (char *)malloc(len + 1);
    if (!buffer) {
        msg_error(hash, "memory allocate\n");
        return NULL;
    }
    memset(buffer, 0, len + 1);

    length = len * 3 / 4 + 1;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        while (bytes < length) {
            n = read(fd, buffer + bytes, length - bytes);
            if (n < 0) {
                break;
            }
            bytes += (size_t)n;
        }
        close(fd);
    }

    if (bytes < length) {
        srand((unsigned)time(NULL));
        for (i = 0; i < length; i++) {
            buffer[i] ^= (char)(255.0 * rand() / RAND_MAX);
        }
    }

    ret = to_base64(buffer, length, len);
    if (ret < 0) {
        free(buffer);
        return NULL;
    }

    buffer[ret] = 0;

    return buffer;
}

char *
password_hash(const char *password, const char *algo,
              const char *salt, const int cost)
{
    char *gensalt = NULL, *hash = NULL, *output = NULL;
    char format[FORMAT_LEN];
    size_t output_len = BLOWFISH_LEN + 1;
    size_t salt_required_len = BCRYPT_BLOWFISH_SALT_REQUIRED_LEN;
    size_t format_len, salt_len;

    if (!password) {
        msg_error(hash, "missing password\n");
        return NULL;
    }

    if (cost < 4 || cost > 31) {
        msg_error(hash, "invalid bcrypt cost parameter specified: %d\n", cost);
        return NULL;
    }

    if (salt) {
        salt_len = strlen(salt);
        gensalt = (char *)malloc(salt_len + 1);
        if (!gensalt) {
            msg_verbose(hash, "memory allocate\n");
            return NULL;
        }
        memcpy(gensalt, salt, salt_len);
        gensalt[salt_len] = 0;

        if (salt_len < salt_required_len) {
            free(gensalt);
            msg_verbose(hash, "provided salt is too short: %ld expecting %ld\n",
                        salt_len, salt_required_len);
            return NULL;
        } else if (is_alphabet(gensalt, salt_len) < 0) {
            int len = to_base64(gensalt, salt_len, salt_len);
            if (len < 0) {
                free(gensalt);
                msg_verbose(hash, "provided salt is not alphabet\n");
                return NULL;
            }
            gensalt[len] = 0;
            salt_len = strlen(gensalt);
        }
    } else {
        gensalt = make_salt(salt_required_len);
        if (!gensalt) {
            msg_verbose(hash, "generated salt\n");
            return NULL;
        }
        salt_len = strlen(gensalt);
    }

    msg_verbose(hash,"parameters\n"
                "  password  => %s\n"
                "  algorithm => %s\n"
                "  salt      => %s\n"
                "  cost      => %d\n",
                password, algo, gensalt, cost);

    memset(format, 0, sizeof(format));
    sprintf(format, "$2y$%02d$", cost);
    format_len = strlen(format);

    hash = malloc(format_len + salt_len + 1);
    if (!hash) {
        msg_verbose(hash, "memory allocate\n");
        free(gensalt);
        return NULL;
    }

    sprintf(hash, "%s%s", format, gensalt);
    hash[format_len + salt_len] = 0;

    free(gensalt);

    msg_verbose_ex(hash, 2, "hash => %s\n", hash);

    output = malloc(output_len);
    if (!output) {
        free(hash);
        msg_verbose(hash, "memory allocate\n");
        return NULL;
    }

    memset(output, 0, output_len);

    if (_crypt_blowfish_rn(password, hash, output, output_len) == NULL) {
        free(hash);
        free(output);
        msg_verbose(hash, "blowfish run.\n");
        return NULL;
    }

    free(hash);

    if (strlen(output) <= 13) {
        free(output);
        msg_verbose(hash, "hash length.\n");
        return NULL;
    }

    return output;
}

int
password_verify(const char *password, const char *hash)
{
    char output[BLOWFISH_LEN+1];
    size_t i, len;
    int status = 0;

    if (!password) {
        msg_error(verify, "missing password\n");
        return -1;
    }
    if (!hash) {
        msg_error(verify, "missing hash\n");
        return -1;
    }

    msg_verbose(verify, "parameters\n"
                "  password => %s\n"
                "  hash     => %s\n",
                password, hash);

    memset(output, 0, sizeof(output));

    if (_crypt_blowfish_rn(password, hash, output, sizeof(output)) == NULL) {
        msg_verbose(verify, "blowfish run.\n");
        return -1;
    }

    len = strlen(output);
    if (len != strlen(hash) || len <= 13) {
        msg_verbose(verify, "hash length.\n");
        return -1;
    }

    for (i = 0; i < len; i++) {
        status |= (output[i] ^ hash[i]);
    }

    if (status != 0) {
        return -1;
    }

    return 0;
}

int
password_get_info(const char *hash, char **algo, int *cost)
{
    size_t len;

    *algo = NULL;
    *cost = 0;

    if (!hash) {
        msg_error(get_info, "missing hash\n");
        return -1;
    }

    msg_verbose(get_info, "hash => %s\n", hash);

    len = strlen(hash);

    if (len > 3 && len == 60 &&
        hash[0] == '$' && hash[1] == '2' && hash[2] == 'y') {
        *algo = BCRYPT_BLOWFISH;
        sscanf(hash, "$2y$%d$", cost);
    } else {
        *algo = "unknown";
    }

    return 0;
}
