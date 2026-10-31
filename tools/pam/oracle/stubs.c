#include <stdarg.h>
#include <stdio.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

void pam_vsyslog(const pam_handle_t *pamh, int priority, const char *format, va_list args)
{
	(void)pamh;
	(void)priority;
	fputs("[pam] ", stderr);
	vfprintf(stderr, format, args);
	fputc('\n', stderr);
}

void pam_syslog(const pam_handle_t *pamh, int priority, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	pam_vsyslog(pamh, priority, format, args);
	va_end(args);
}
