#include <cutter.h>
#include "../src/password.h"

extern int msgno;

void
test_success()
{
    cut_assert_equal_int(
        0,
        password_verify(
            "password",
            "$2y$10$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK"));
}

void
test_args_none()
{
    msgno = -1;
    cut_assert_equal_int(-1, password_verify(NULL, NULL));
}

void
test_args_only_password()
{
    msgno = -1;
    cut_assert_equal_int(-1, password_verify("password", NULL));
}

void
test_args_only_hash()
{
    msgno = -1;
    cut_assert_equal_int(
        -1,
        password_verify(
            NULL,
            "$2y$10$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK"));
}

void
test_args_invalid_password()
{
    msgno = -1;
    cut_assert_equal_int(
        -1,
        password_verify(
            "test",
            "$2y$10$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK"));
}

void
test_args_invalid_hash_format()
{
    msgno = -1;
    cut_assert_equal_int(-1, password_verify("password", "hash"));
}

void
test_args_invalid_hash()
{
    msgno = -1;
    cut_assert_equal_int(
        -1,
        password_verify(
            "password",
            "$2y$10$Abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK"));
}
