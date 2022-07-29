/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __KILLSNOOP_H
#define __KILLSNOOP_H

#define TASK_COMM_LEN 16

struct val_t {
	__u32 pid;
	int sig;
	int tpid;
	char comm[TASK_COMM_LEN];
};

struct data_t {
	__u32 pid;
	int tpid;
	int sig;
	int ret;
	char comm[TASK_COMM_LEN];
};
