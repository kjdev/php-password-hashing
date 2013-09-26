#include <cutter.h>
#include "../src/password.h"

extern int msgno;

void
test_success()
{
    char *algo;
    int cost;

    cut_assert_equal_int(
        0, password_get_info(
            "$2y$10$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK",
            &algo, &cost));
    cut_assert_equal_string(BCRYPT_BLOWFISH, algo);
    cut_assert_equal_int(BCRYPT_BLOWFISH_COST, cost);
}

void
test_args_none()
{
    char *algo;
    int cost;

    msgno = -1;
    cut_assert_equal_int(-1, password_get_info(NULL, &algo, &cost));
    cut_assert_null(algo);
    cut_assert_equal_int(cost, 0);
}

void
test_invalid_hash()
{
    char *algo;
    int cost;

    cut_assert_equal_int(0, password_get_info("test", &algo, &cost));
    cut_assert_equal_string("unknown", algo);
    cut_assert_equal_int(cost, 0);
}

void
test_cost()
{
    char *algo;
    int cost;

    cut_assert_equal_int(
        0, password_get_info(
            "$2y$17$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK",
            &algo, &cost));
    cut_assert_equal_string(BCRYPT_BLOWFISH, algo);
    cut_assert_equal_int(cost, 17);
}
