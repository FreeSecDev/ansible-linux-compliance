#include "pam_pwhistory.c"

int main(int argc, char **argv)
{
	options_t options;
	int count = argc - 1;
	const char **args = (const char **)(argv + 1);

	memset(&options, 0, sizeof(options));
	options.remember = 10;
	options.tries = 1;
	parse_config_file((pam_handle_t *)1, count, args, &options);
	for (int i = 0; i < count; ++i)
		parse_option((pam_handle_t *)1, args[i], &options);
	printf("{\"remember\": %d, \"enforce_for_root\": %d}\n", options.remember,
	       options.enforce_for_root);
	return 0;
}
