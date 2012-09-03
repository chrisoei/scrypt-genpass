/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "scrypt_platform.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "readpass.h"
#include "genpass.h"
#include "warn.h"

static void
usage(void)
{

	fprintf(stderr,
	    "usage: scrypt-genpass <site>\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	FILE * infile = NULL;
	FILE * outfile = stdout;
	int dec = 0;
	size_t maxmem = 0;
	double maxmemfrac = 0.5;
	int megaops = 5;
	char ch;
	char * passwd;
	int rc;
	int i;

#ifdef NEED_WARN_PROGNAME
	warn_progname = "scrypt";
#endif

	if (argc < 1)
		usage();
	maxmem = 0;
	maxmemfrac = 0.125;

	/* Parse arguments. */
	while ((ch = getopt(argc, argv, "hm:M:o:")) != -1) {
		switch (ch) {
		case 'M':
			maxmem = strtoumax(optarg, NULL, 0);
			break;
		case 'm':
			maxmemfrac = strtod(optarg, NULL);
			break;
		case 'o':
			megaops = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* We must have one parameters left. */
	if (argc != 1)
		usage();

	/* Prompt for a password. */
	if (tarsnap_readpass(&passwd, "Please enter passphrase",
	    dec ? NULL : "Please confirm passphrase", 1))
		exit(1);

	uint8_t dk[64];
	rc = genpass(dk, (uint8_t *)passwd,
	    strlen(passwd), maxmem, maxmemfrac, megaops);

	/* Zero and free the password. */
	memset(passwd, 0, strlen(passwd));
	free(passwd);

	char* buf = malloc(65);
	for (i = 0; i < 64; i++) {
		sprintf(buf + i, "%x", dk[i]);
	}
	printf("Result: %s\n", buf);

	/* If we failed, print the right error message and exit. */
	if (rc != 0) {
		switch (rc) {
		case 1:
			warn("Error determining amount of available memory");
			break;
		case 2:
			warn("Error reading clocks");
			break;
		case 3:
			warn("Error computing derived key");
			break;
		case 4:
			warn("Error reading salt");
			break;
		case 5:
			warn("OpenSSL error");
			break;
		case 6:
			warn("Error allocating memory");
			break;
		case 7:
			warnx("Input is not valid scrypt-encrypted block");
			break;
		case 8:
			warnx("Unrecognized scrypt format version");
			break;
		case 9:
			warnx("Decrypting file would require too much memory");
			break;
		case 10:
			warnx("Decrypting file would take too much CPU time");
			break;
		case 11:
			warnx("Passphrase is incorrect");
			break;
		case 12:
			warn("Error writing file: %s",
			    (argc > 1) ? argv[1] : "standard output");
			break;
		case 13:
			warn("Error reading file: %s", argv[0]);
			break;
		}
		exit(1);
	}

	return (0);
}
