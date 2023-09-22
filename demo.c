#include "zuri.h"

#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
	const char *sample = "http://root@localhost:8080/v1?ask#sub";

	struct zuri2k uri;
	zuri_parse2k(&uri, sample, strlen(sample));

	char buf[2048];
	size_t len = zuri_read2k(&uri, &buf[0], sizeof(buf) - 1);
	if (len == 0) {
		printf("%lu-byte buffer won't fit URI with null terminator", sizeof(buf));
		return 1;
	}

	printf("rebuild as a %zu-byte URI: %s\n", len, &buf[0]);
	return 0;
}
