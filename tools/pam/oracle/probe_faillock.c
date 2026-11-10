#include "pam_faillock.c"

int main(int argc, char **argv)
{
	struct options opts;
	int rv = args_parse((pam_handle_t *)1, argc - 1, (const char **)(argv + 1), 0, &opts);

	printf("{\"rv\": %d, \"deny\": %u, \"fail_interval\": %u, \"unlock_time\": %u, "
	       "\"root_unlock_time\": %u, \"even_deny_root\": %d, \"audit\": %d, \"silent\": %d}\n",
	       rv, (unsigned int)opts.deny, opts.fail_interval, opts.unlock_time,
	       opts.root_unlock_time, !!(opts.flags & FAILLOCK_FLAG_DENY_ROOT),
	       !!(opts.flags & FAILLOCK_FLAG_AUDIT), !!(opts.flags & FAILLOCK_FLAG_SILENT));
	return 0;
}
