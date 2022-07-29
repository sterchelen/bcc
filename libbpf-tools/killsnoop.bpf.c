#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "killsnoop.h"


const volatile pid_t target_pid = -1;
const volatile int target_sig = -1;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

BPF_HASH(infotmp, u32, struct val_t);

int syscall__kill(struct pt_regs *ctx, int tpid, int sig)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	
	if (target_pid != -1 && target_pid != pid)
		return 0;
	if (target_sig != -1 && target_sig != sig)
		return 0
	
	struct val_t val = {.pid = pid};
	if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
		val.tpid = tpid;
		val.sig = sig;
		infotmp.update(&tid, &val);
	}
	
	return 0;
};

int do_ret_sys_kill(struct pt_regs *ctx)
{
	struct data_t data = {};
	struct val_t *valp;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	
	valp = infotmp.lookup(&tid);
	if (valp == 0) {
		// missed entry
		return 0;
	}
	
	bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
	data.pid = pid;
	data.tpid = valp->tpid;
	data.ret = PT_REGS_RC(ctx);
	data.sig = valp->sig;
	
	events.perf_submit(ctx, &data, sizeof(data));
	infotmp.delete(&tid);
	
	return 0;
}

