AUTOMAKE_OPTIONS = subdir-objects dist-lzip
SUBDIRS = tests
bin_PROGRAMS = bruteforce-salted-openssl
bruteforce_salted_openssl_SOURCES = src/bruteforce-salted-openssl.c src/version.h
dist_man_MANS = doc/bruteforce-salted-openssl.1
EXTRA_DIST = \
	tests/crack-encrypted1.sh \
	tests/crack-encrypted2.sh \
	tests/crack-encrypted3.sh \
	tests/crack-encrypted4.sh \
	tests/dict.txt \
	tests/encrypted1.dat \
	tests/encrypted2.dat \
	tests/encrypted3.dat \
	tests/encrypted4.dat \
	tests/message.txt
