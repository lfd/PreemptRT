
/*
 * Copyright (C) 2005, Ingo Molnar <mingo@redhat.com>
 *
 * user-triggered tracing.
 *
 * The -rt kernel has a built-in kernel tracer, which will trace
 * all kernel function calls (and a couple of special events as well),
 * by using a build-time gcc feature that instruments all kernel
 * functions.
 *
 * The tracer is highly automated for a number of latency tracing purposes,
 * but it can also be switched into 'user-triggered' mode, which is a
 * half-automatic tracing mode where userspace apps start and stop the
 * tracer. This file shows a dumb example how to turn user-triggered
 * tracing on, and how to start/stop tracing. Note that if you do
 * multiple start/stop sequences, the kernel will do a maximum search
 * over their latencies, and will keep the trace of the largest latency
 * in /proc/latency_trace. The maximums are also reported to the kernel
 * log. (but can also be read from /proc/sys/kernel/preempt_max_latency)
 *
 * For the tracer to be activated, turn on CONFIG_EVENT_TRACING
 * in the .config, rebuild the kernel and boot into it. The trace will
 * get _alot_ more verbose if you also turn on CONFIG_FUNCTION_TRACING,
 * every kernel function call will be put into the trace. Note that
 * CONFIG_FUNCTION_TRACING has significant runtime overhead, so you dont
 * want to use it for performance testing :)
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/unistd.h>

int main (int argc, char **argv)
{
	int ret;

	if (getuid() != 0) {
		fprintf(stderr, "needs to run as root.\n");
		exit(1);
	}
	ret = system("cat /proc/sys/kernel/mcount_enabled >/dev/null 2>/dev/null");
	if (ret) {
		fprintf(stderr, "CONFIG_LATENCY_TRACING not enabled?\n");
		exit(1);
	}
	system("echo 1 > /proc/sys/kernel/trace_user_triggered");
	system("[ -e /proc/sys/kernel/wakeup_timing ] && echo 0 > /proc/sys/kernel/wakeup_timing");
	system("echo 1 > /proc/sys/kernel/trace_enabled");
	system("echo 1 > /proc/sys/kernel/mcount_enabled");
	system("echo 0 > /proc/sys/kernel/trace_freerunning");
	system("echo 0 > /proc/sys/kernel/trace_print_on_crash");
	system("echo 0 > /proc/sys/kernel/trace_verbose");
	system("echo 0 > /proc/sys/kernel/preempt_thresh 2>/dev/null");
	system("echo 0 > /proc/sys/kernel/preempt_max_latency 2>/dev/null");

	// start tracing
	if (prctl(0, 1)) {
		fprintf(stderr, "trace-it: couldnt start tracing!\n");
		return 1;
	}
	usleep(10000000);
	if (prctl(0, 0)) {
		fprintf(stderr, "trace-it: couldnt stop tracing!\n");
		return 1;
	}

	system("echo 0 > /proc/sys/kernel/trace_user_triggered");
	system("echo 0 > /proc/sys/kernel/trace_enabled");
	system("cat /proc/latency_trace");

	return 0;
}


