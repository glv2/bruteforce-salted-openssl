AC_INIT(bruteforce_salted_openssl, 1.4.2)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(src/bruteforce-salted-openssl.c)

dnl Check for toolchain and install components
AC_PROG_CC
AC_PROG_INSTALL

dnl Check for standard headers
AC_CHECK_HEADERS([ctype.h fcntl.h locale.h math.h stdio.h stdlib.h string.h sys/stat.h sys/time.h sys/types.h time.h unistd.h wchar.h])

dnl Check for functions
AC_CHECK_FUNCS([calloc malloc realloc free])
AC_CHECK_FUNCS([perror printf fprintf snprintf])
AC_CHECK_FUNCS([fopen fgetc])
AC_CHECK_FUNCS([atoi atol isprint isspace])
AC_CHECK_FUNCS([memset strcasecmp strlen strncmp strncpy])
AC_CHECK_FUNCS([setlocale mbstowcs wcsncpy wcstombs])
AC_CHECK_FUNCS([open fstat read close])
AC_CHECK_FUNCS([getopt])
AC_CHECK_FUNCS([signal])
AC_CHECK_FUNCS([localtime setitimer strftime time])

dnl Check for libraries
AC_CHECK_LIB(m, pow, [], AC_MSG_ERROR([math library required]))

AC_CHECK_LIB(pthread, pthread_create, [], AC_MSG_ERROR([POSIX threads library required]))
AC_CHECK_HEADERS(pthread.h, [], AC_MSG_ERROR([POSIX threads headers required]))

AC_CHECK_LIB(crypto, EVP_get_cipherbyname, [], AC_MSG_ERROR([OpenSSL libraries required]))
AC_CHECK_HEADERS(openssl/evp.h, [], AC_MSG_ERROR([OpenSSL headers required]))

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
