SRC=	ssltest.o
TARGETS=	ssltest
LDFLAGS=	-lcrypto

all:	$(TARGETS)

$(TARGETS):	$(SRC)
		$(CC) -o $@ $< $(LDFLAGS)

clean:	
	-rm $(SRC) $(TARGETS)


