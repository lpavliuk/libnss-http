# Makefile

#### Start of system configuration section. ####

CC = gcc
INSTALL = /usr/bin/install
INSTALL_DATA = ${INSTALL} -m 644

LIB_DIR = /lib64

#### End of system configuration section. ####

all:	libnss_http

libnss_http:	libnss_http.c
	${CC} ${CFLAGS} ${LDFLAGS} -fPIC -Wall -shared -o libnss_http.so.2 \
		-Wl,-soname,libnss_http.so.2 libnss_http.c

install:	
	${INSTALL_DATA} libnss_http.so.2 ${LIB_DIR}/libnss_http-2.3.6.so
	cd ${LIB_DIR} && ln -fs libnss_http-2.3.6.so libnss_http.so.2
	cp libnss-http.conf /etc/libnss-http.conf

clean:
	rm -f libnss_http.so.2
