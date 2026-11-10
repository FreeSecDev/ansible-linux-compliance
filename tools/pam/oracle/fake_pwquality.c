/*
 * A stand-in for pam_pwquality.so that records, as one JSON array per line, the arguments that
 * the real libpam passes to it in the preliminary check of pam_chauthtok, in the file named by
 * FREESECDEV_PAM_PROBE_LOG. probe-in-image.sh installs it over the module of the throwaway
 * container, so that the probe sees exactly which pam_pwquality lines libpam runs and with which
 * arguments, as it assembles, splits and includes the service files (FREES-212).
 */
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_modules.h>

static void put_json_string(FILE *out, const char *text)
{
	const unsigned char *p;

	fputc('"', out);
	for (p = (const unsigned char *)text; *p; ++p) {
		if (*p == '"' || *p == '\\')
			fprintf(out, "\\%c", *p);
		else if (*p < 0x20 || *p == 0x7f)
			fprintf(out, "\\u%04x", *p);
		else
			fputc(*p, out);
	}
	fputc('"', out);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *path = getenv("FREESECDEV_PAM_PROBE_LOG");
	FILE *out;
	int i;

	(void)pamh;
	if (!(flags & PAM_PRELIM_CHECK) || path == NULL || (out = fopen(path, "a")) == NULL)
		return PAM_SUCCESS;
	fputc('[', out);
	for (i = 0; i < argc; i++) {
		if (i)
			fputc(',', out);
		put_json_string(out, argv[i]);
	}
	fputs("]\n", out);
	fclose(out);
	return PAM_SUCCESS;
}
