/*	$OpenBSD$	*/
/*
 * Copyright (c) 2015 Martin Pieuchot
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef round_page
#define	round_page(x)	(((x) + PAGE_MASK) & ~PAGE_MASK)
#endif

enum {
	D_SOLARIS = 0,
	D_ANON,
	D_ALL,
	D_DEBUG,
	D_LINUX,
	D_MAP,
} 		 display;
int		 verbose;

__dead void	 usage(void);
int		 dump(pid_t);
void		 print_all(struct kinfo_vmentry *);
void		 print_solaris(struct kinfo_vmentry *);
const char	*kveprot(int);
const char	*kveprotection(struct kinfo_vmentry *);
const char	*kvetype(struct kinfo_vmentry *, unsigned long, size_t);

__dead void
usage(void)
{
	extern const char *__progname;
	fprintf(stderr, "usage: %s [-aPs] [-p pid] [pid ...]\n",  __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	pid_t pid = -1;
	int ch, rc = 0;

	while ((ch = getopt(argc, argv, "aPp:s")) != -1) {
		switch (ch) {
		case 'a':
			display = D_ALL;
			break;
		case 'p':
			pid = (pid_t)strtonum(optarg, 0, UINT_MAX, NULL);
			break;
		case 'P':
			pid = getpid();
			break;
		case 's':
			display = D_SOLARIS;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (pid == -1 && argc == 0)
		pid = getppid();

	if (pid != -1)
		rc = dump(pid);

	while (rc == 0 && argc > 0) {
		pid = (pid_t)strtonum(argv[0], 0, UINT_MAX, NULL);
		argv++;
		argc--;
		rc = dump(pid);
	}

	return (rc);
}

int
dump(pid_t pid)
{
	struct kinfo_vmentry *kve;
	char *buf = NULL, *next, *lim = NULL;
	unsigned long sp, total = 0;
	struct _ps_strings _ps;
	int mib[3], mcnt;
	struct rlimit rl;
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_VMMAP;
	mib[2] = pid;
	mcnt = 3;
	while (1) {
		if (sysctl(mib, mcnt, NULL, &len, NULL, 0) == -1)
			err(1, "vmmap sysctl estimate");
		if (len == 0)
			break;
#ifndef needkernelfix
		if (len % sizeof(*kve) != 0) {
			len = ((len - 1) / sizeof(*kve)) * sizeof(*kve);
		}
#endif
		if ((buf = realloc(buf, len)) == NULL)
			err(1, NULL);
		if (sysctl(mib, mcnt, buf, &len, NULL, 0) == -1) {
			if (errno == ENOMEM)
				continue;
			err(1, "vmmap sysctl");
		}
		lim = buf + len;
		break;
	}

	if (buf == NULL)
		return (-1);

	if (getrlimit(RLIMIT_STACK, &rl) != 0)
		return (EAGAIN);

	mib[0] = CTL_VM;
	mib[1] = VM_PSSTRINGS;
	mib[2] = pid;
	len = sizeof(_ps);
	if (sysctl(mib, 2, &_ps, &len, NULL, 0) != 0)
		err(1, "psstrings sysctl");

#ifdef MACHINE_STACK_GROWS_UP
	sp = (unsigned long)_ps.val;
#else
	sp = (unsigned long)round_page((uintptr_t)_ps.val);
#endif

	if (display == D_ALL)
		printf("%-*s %-*s %*s %-*s rwxpc  RWX  I/W/A Dev  %*s - File\n",
		    (int)sizeof(long) * 2, "Start",
		    (int)sizeof(long) * 2, "End",
		    (int)sizeof(int)  * 2, "Size ",
		    (int)sizeof(long) * 2, "Offset",
		    (int)sizeof(int)  * 2, "Inode");

	for (next = buf; next < lim; next += sizeof(*kve)) {
		struct kinfo_vmentry *kve = (struct kinfo_vmentry *)next;

		if (display == D_ALL)
			print_all(kve);
		else
			print_solaris(kve);
		printf("%s\n", kvetype(kve, sp, (size_t)rl.rlim_cur));

		if (kve->kve_protection)
			total += (kve->kve_end - kve->kve_start);
	}

	if (display == D_ALL)
		printf("%-*s %9luk\n", (int)sizeof(void *) * 4 - 1, " total",
		    total / 1024);
	else
		printf("%-*s %8luk\n", (int)sizeof(void *) * 2 - 2, " total",
		    total / 1024);

	return (0);
}

void
print_all(struct kinfo_vmentry *kve)
{
	unsigned long size = (kve->kve_end - kve->kve_start) / 1024;
	ino_t inode = 0;
	dev_t dev = 0;

	printf("%0*lx-%0*lx %7luk %0*lx %s%c%c (%s) %d/%d/%d %02d:%02d %7llu - ",
	    (int)sizeof(void *) * 2, kve->kve_start,
	    (int)sizeof(void *) * 2,
	    kve->kve_end - (kve->kve_start != kve->kve_end ? 1 : 0),
	    size,
	    (int)sizeof(void *) * 2, (unsigned long)kve->kve_offset,
	    kveprot(kve->kve_protection),
	    (kve->kve_etype & KVE_ET_COPYONWRITE) ? 'p' : 's',
	    (kve->kve_etype & KVE_ET_NEEDSCOPY) ? '+' : '-',
	    kveprot(kve->kve_max_protection),
	    kve->kve_inheritance, kve->kve_wired_count, kve->kve_advice,
	    major(dev), minor(dev), (unsigned long long)inode);
}

void
print_solaris(struct kinfo_vmentry *kve)
{
	unsigned long size = (kve->kve_end - kve->kve_start) / 1024;

	printf("%0*lX %6luK %-15s   ", (int)sizeof(void *) * 2,
	    kve->kve_start, size, kveprotection(kve));
}

const char *
kveprot(int prot)
{
	static const char *prots[] = { "---", "r--", "rw-", "r-x", "rwx" };
	return (prots[(prot + 1) / 2]);
}

const char *
kveprotection(struct kinfo_vmentry *kve)
{
	static const char *protections[] = {
	    "", "read", "read/write", "read/exec", "read/write/exec"
	};
	return (protections[(kve->kve_protection + 1) / 2]);
}

const char *
kvetype(struct kinfo_vmentry *kve, unsigned long sp, size_t ssize)
{
	if (kve->kve_start >= (sp - ssize) && kve->kve_end <= sp)
		return ("  [ stack ]");

	if (kve->kve_etype & KVE_ET_OBJ)
		return ("  [ obj ]");

	if (kve->kve_etype & KVE_ET_HOLE)
		return ("  [ hole ]");

	return ("  [ anon ]");
}
