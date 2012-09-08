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
	    "usage: scrypt-genpass [-l LEN] [-m MAXMEM] [-n] [-o MAXOPS] [-k KEYFILE] [-p PASS] <site>\n");
	fprintf(stderr,
			"       scrypt-genpass -t\n");
	exit(1);
}

void unit_tests()
{
	if (sizeof(char)!=1) {
		fprintf(stderr, "sizeof(char) != 1\n");
		exit(1);
	}

	uint8_t testhash[32];
	sha256string(testhash, (uint8_t*) "abc", 3);
	char testbuf[65];
	bintohex(testbuf, 32, testhash);
	if (strcmp(testbuf, 
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
		fprintf(stderr, "SHA256 test failed\n");
		exit(1);
	}

	fprintf(stderr, "All internal tests pass\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	FILE * infile = NULL;
	FILE * outfile = stdout;
	int dec = 0;
	size_t passwdlen = 0;
	size_t outputlength = 16;
	uint32_t maxmem = 1000;
	uint32_t megaops = 32;
	char ch;
	char * keyfile = NULL;
	uint8_t* passwd = NULL;
	int numbers_only = 0;
	int rc;

#ifdef NEED_WARN_PROGNAME
	warn_progname = "scrypt-genpass";
#endif

	if (argc < 1)
		usage();

	/* Parse arguments. */
	while ((ch = getopt(argc, argv, "htk:l:m:no:p:")) != -1) {
		switch (ch) {
		case 'k':
			keyfile = strdup(optarg);
			break;
		case 'l':
			outputlength = atoi(optarg);
			break;
		case 'm':
			maxmem = atoi(optarg);
			break;
		case 'n':
			numbers_only++;
			break;
		case 'o':
			megaops = atoi(optarg);
			break;
		case 'p':
			passwd = strdup(optarg);
			break;
		case 't':
			unit_tests();
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

	if (!passwd) {
		/* Prompt for a password. */
		if (tarsnap_readpass((char**)&passwd, "Please enter passphrase",
		    dec ? NULL : "Please confirm passphrase", 1))
			exit(1);
	}
	passwdlen = strlen(passwd);

	if (keyfile) {
		FILE *fp;
		size_t keyfilelen;

		fp = fopen(keyfile, "rb");
		if (fp) {
			fseek(fp, 0, SEEK_END);
			keyfilelen = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			uint8_t* combinedkey = malloc(passwdlen + keyfilelen + 1);
			if (combinedkey) {
				strcpy(combinedkey, passwd);
				memset(passwd, 0, passwdlen);
				free(passwd);
				size_t n  = fread(combinedkey + passwdlen, keyfilelen, 1, fp);
				fclose(fp);
				if (n != 1) {
					warn("Unable to read keyfile");
					exit(1);
				}
				passwd = combinedkey;
				passwdlen += keyfilelen;
			} else {
				warn("Unable to allocate memory for combined key");
				exit(1);
			}
		}	else {
			warn("Unable to open keyfile %s", keyfile);
			exit(1);
		}
	}

	uint8_t passhash[32];
	sha256string(passhash, passwd, passwdlen);
	char buf1[65];
	bintohex(buf1, 32, passhash);
	printf("Master hex: %s\n", buf1);
	memset(buf1, 0, 65);

	uint8_t dk[64];
	rc = genpass(dk, (uint8_t *)passwd, passwdlen, (void*) *argv,
		maxmem, megaops);

	/* Zero and free the password. */
	memset(passwd, 0, passwdlen);
	free(passwd);
	free(keyfile);

	char buf[129];
	bintohex(buf, 64, dk);
	printf("Pass hex: %s\n", buf);
	memset(buf, 0, 129);

	if ((outputlength < 3)||(outputlength > 64)) {
		warn("Unable to generate password for output length %lu", outputlength);
		exit(1);
	}

	char output[outputlength + 1];
	hashtopass(numbers_only, output, outputlength, dk);
	printf("Generated password: %s\n", output);
	memset(output, 0, outputlength + 1);

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
		case 14:
			warn("Unable to open keyfile: %s", keyfile);
			break;
		case 15:
			warn("Unable to allocate memory for combined key");
			break;
		}
		exit(1);
	}

	return (0);
}
