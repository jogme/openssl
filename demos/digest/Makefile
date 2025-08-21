#
# To run the demos when linked with a shared library (default) ensure
# that libcrypto is on the library path. For example:
#
#    LD_LIBRARY_PATH=../.. ./EVP_MD_demo

TESTS = EVP_MD_demo \
        EVP_MD_stdin \
        OPENSSL_BOX_EVP_MD_xof \
        OPENSSL_BOX_BIO_f_md

CFLAGS  = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS  = -lcrypto

all: $(TESTS)

EVP_MD_demo: EVP_MD_demo.o
EVP_MD_stdin: EVP_MD_stdin.o
OPENSSL_BOX_EVP_MD_xof: OPENSSL_BOX_EVP_MD_xof.o
OPENSSL_BOX_BIO_f_md: OPENSSL_BOX_BIO_f_md.o

$(TESTS):
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) *.o $(TESTS)

.PHONY: test
# Since some of these tests use stdin, we use the source file as stdin
# when running the tests
test: all
	@echo "\nDigest tests:"
	@set -e; for tst in $(TESTS); do \
		echo "\n"$$tst; \
		cat $$tst.c | ./$$tst; \
	done
