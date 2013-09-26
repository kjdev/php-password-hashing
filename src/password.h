#ifndef __PHP_PASSWORD_HASHING_PASSWORD_H__
#define __PHP_PASSWORD_HASHING_PASSWORD_H__

#define FORMAT_LEN 10
#define BLOWFISH_LEN 60

#define BCRYPT_BLOWFISH "bcrypt"
#define BCRYPT_BLOWFISH_COST 10
#define BCRYPT_BLOWFISH_SALT_REQUIRED_LEN 22

extern char * password_hash(const char *password, const char *algo, const char *salt, const int cost);
extern int password_verify(const char *password, const char *hash);
extern int password_get_info(const char *hash, char **algo, int *cost);

#endif
