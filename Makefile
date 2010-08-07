dis: dis.c
	${CC} ${CPPFLAGS} ${CFLAGS} -o $@ dis.c ${LDADD}

clean:
	rm -f dis


