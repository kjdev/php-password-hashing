# PHP Password Hashing Command

PHP Password Hashing by C.

## Build

```
% mkdir build && cd build
% cmake -DCMAKE_BUILD_TYPE=Release ..
% make
% make install
```

### Test

Required: [cutter](http://cutter.sourceforge.net/index.html)

```
% make && make test
```

or

```
% make && cutter .
```

### Coverage

```
% cmake -DCMAKE_BUILD_TYPE=Coverage ..
% make && make test
% lcov -c -d ./tests/CMakeFiles/test_php_password_hashing.dir/__/src/ -o test.cov
% genhtml --no-branch-coverage -f -o ./coverage ./test.cov
```

## Command

### php\_password\_hash — Creates a password hash

**php\_password\_hash** -p \<PASSWORD\> \[-a \<ALGORITHM\>\] \[-s \<SALT\>\] \[-c \<COST\>\]

* -p, --password=PASSWORD : users's password
* -a, --algorithm=ALGORITHM : hashing algorithm (no used) [DEFAULT: bcrypt]
* -s, --salt=SALT : salt to use when hashing the password
* -c, --cost=COST : cost that should be used [DEFAULT: 10]

### php\_password\_verify — Verifies that a password matches a hash

**php\_password\_verify** -p \<PASSWORD\> -h \<HASH\>

* -p, --password=PASSWORD : users's password.
* -h, --hash=HASH : password hashed.

### php\_password\_get_info — Returns information about the given hash

**php\_password\_get\_info** -h \<HASH\>

* -h, --hash=HASH : password hashed
