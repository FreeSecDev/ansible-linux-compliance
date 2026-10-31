/*
 * Print the logical lines of a PAM service file as libpam assembles them and the tokens that
 * libpam's own _pam_StrTok splits each into, as JSON: {"lines": [[token, ...], ...], "end": x},
 * where end is the last return value of _pam_assemble_line (0 at the end of the file, -1 when it
 * stops at an error).
 *
 * PAM_LINE_BUFFER selects the line-buffer reader of linux-pam 1.5.1 (Rocky Linux 9); without it,
 * the fixed-buffer reader of the Ubuntu 1.5.3 package is used.
 */
#include "pam_handlers.c"

static void put_json_string(const char *text)
{
	const unsigned char *p;

	putchar('"');
	for (p = (const unsigned char *)text; *p; ++p) {
		if (*p == '"' || *p == '\\')
			printf("\\%c", *p);
		else if (*p < 0x20 || *p == 0x7f)
			printf("\\u%04x", *p);
		else
			putchar(*p);
	}
	putchar('"');
}

static void put_tokens(const char *line, int first)
{
	char *copy = strdup(line);
	char *next = NULL;
	char *token;
	int count = 0;

	if (!first)
		putchar(',');
	putchar('[');
	for (token = _pam_StrTok(copy, " \n\t", &next); token != NULL;
	     token = _pam_StrTok(NULL, " \n\t", &next)) {
		if (count++)
			putchar(',');
		put_json_string(token);
	}
	putchar(']');
	free(copy);
}

int main(int argc, char **argv)
{
	FILE *f;
	int x;
	int first = 1;

	if (argc != 2 || (f = fopen(argv[1], "r")) == NULL) {
		printf("null\n");
		return 0;
	}
	printf("{\"lines\": [");
#ifdef PAM_LINE_BUFFER
	{
		struct line_buffer buffer;

		_pam_buffer_init(&buffer);
		while ((x = _pam_assemble_line(f, &buffer)) > 0) {
			put_tokens(buffer.assembled, first);
			first = 0;
		}
		_pam_buffer_clear(&buffer);
	}
#else
	{
		char buf[BUF_SIZE];

		while ((x = _pam_assemble_line(f, buf, BUF_SIZE)) > 0) {
			put_tokens(buf, first);
			first = 0;
		}
	}
#endif
	printf("], \"end\": %d}\n", x);
	fclose(f);
	return 0;
}
