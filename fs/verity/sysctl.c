/* SPDX-License-Identifier: GPL-2.0 */

#include "fsverity_private.h"

#include <linux/sysctl.h>

static int two = 2;
/*
 * /proc/sys/fs/verity/require_signatures
 * If 1, all verity files must have a valid builtin signature.
 */
int fsverity_require_signatures;
/*
 * /proc/sys/fs/verity/enable
 * If 0, disable verity, don't verify, ignore enable ioctl.
 * If 1, allow enabling verity, but only log on verification failure.
 * If 2, fully enable.
 * default: 2
 */
int fsverity_enable = 2;

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *fsverity_sysctl_header;

static const struct ctl_path fsverity_sysctl_path[] = {
	{ .procname = "fs", },
	{ .procname = "verity", },
	{ }
};

static struct ctl_table fsverity_sysctl_table[] = {
	{
		.procname       = "require_signatures",
		.data           = &fsverity_require_signatures,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "enable",
		.data           = &fsverity_enable,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = &two,
	},
	{ }
};

int __init fsverity_sysctl_init(void)
{
	fsverity_sysctl_header = register_sysctl_paths(fsverity_sysctl_path,
						       fsverity_sysctl_table);
	if (!fsverity_sysctl_header) {
		pr_err("sysctl registration failed!\n");
		return -ENOMEM;
	}
	return 0;
}

void __init fsverity_exit_sysctl(void)
{
	unregister_sysctl_table(fsverity_sysctl_header);
	fsverity_sysctl_header = NULL;
}
#endif /* !CONFIG_SYSCTL */
