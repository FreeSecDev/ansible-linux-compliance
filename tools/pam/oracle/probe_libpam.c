/*
 * Start the real libpam of the image for a service and run pam_chauthtok, so that every
 * pam_pwquality line that libpam assembles for the password stack runs (FREES-212). Prints
 * {"start": <pam_start>, "chauthtok": <pam_chauthtok or -1 when pam_start failed>}.
 */
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>

static int conversation(int count, const struct pam_message **messages,
			struct pam_response **responses, void *data)
{
	(void)messages;
	(void)data;
	*responses = calloc((size_t)count, sizeof(**responses));
	return *responses == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	struct pam_conv conv = { conversation, NULL };
	pam_handle_t *pamh = NULL;
	int start;
	int rv = -1;

	if (argc != 2)
		return 2;
	start = pam_start(argv[1], "root", &conv, &pamh);
	if (start == PAM_SUCCESS) {
		rv = pam_chauthtok(pamh, 0);
		pam_end(pamh, rv);
	}
	printf("{\"start\": %d, \"chauthtok\": %d}\n", start, rv);
	return 0;
}
