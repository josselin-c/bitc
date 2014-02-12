AC_INIT([bitc], [0.1], [austruym@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
Makefile
src/Makefile
])

PKG_CHECK_MODULES([DEPS], [ncurses libssl openssl libcurl])

AC_CHECK_LIB([snappy], [snappy_compress], 
             [ SNAPPY_LIBS="-lsnappy" AC_SUBST([SNAPPY_LIBS]) ], [], [])

AC_CHECK_LIB([leveldb], [leveldb_open], 
             [ LEVELDB_LIBS="-lleveldb" AC_SUBST([LEVELDB_LIBS]) ], 
             [AC_MSG_FAILURE([libleveldb not found])], [-lsnappy -lpthread])
AC_OUTPUT
