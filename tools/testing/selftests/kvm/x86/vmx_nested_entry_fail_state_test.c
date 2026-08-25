// SPDX-License-Identifier: GPL-2.0-only
/*
 * Nested VM-entry failure state test
 *
 * Copyright (C) 2026, Intel, Inc.
 */
#include <asm/msr-index.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "vmx.h"

static gva_t entry_msr_load_list_gva;
static uint64_t entry_msr_load_list_gpa;

enum state_src {
	STATE_SRC_L1,		/* L1's own state */
	STATE_SRC_VMCS12_GUEST,	/* vmcs12->guest_*, i.e. L2's state */
	STATE_SRC_VMCS12_HOST,	/* vmcs12->host_*, i.e. host state to load */
	NR_STATE_SRCS,
};

static bool has_shstk;
struct cet_state {
	uint64_t s_cet;
	uint64_t ssp;
	uint64_t ssp_tbl;
};

struct test_state {
	struct cet_state cet;
};

/*
 * In practice, states of STATE_SRC_L1 and STATE_SRC_VMCS12_HOST should be
 * same, i.e., the state of STATE_SRC_VMCS12_HOST is copied from host (L1).
 *
 * But in this test, to distinguish the "load (host) state" operation, make
 * STATE_SRC_VMCS12_HOST different from STATE_SRC_L1.
 */
static const struct test_state states[NR_STATE_SRCS] = {
	[STATE_SRC_L1] = {
		.cet = {
			.s_cet		= CET_SHSTK_EN,
			/*
			 * SSP is not an MSR; the L1 SSP must be configured
			 * using the KVM_SET_ONE_REG ioctl. To simplify the
			 * test logic, checking the other MSRs is enough to
			 * identify the state source, so that there's no need
			 * to configure different SSPs.
			 */
			.ssp		= 0x0000111111111000UL,
			.ssp_tbl	= 0x0000123456789000UL,
		}
	},
	[STATE_SRC_VMCS12_GUEST] = {
		.cet = {
			.s_cet		= CET_SHSTK_EN | CET_WRSS_EN,
			.ssp		= 0x0000111111111000UL,
			.ssp_tbl	= 0x00000abcabcab000UL,
		}
	},
	[STATE_SRC_VMCS12_HOST] = {
		.cet = {
			.s_cet		= CET_WRSS_EN,
			.ssp		= 0x0000111111111000UL,
			.ssp_tbl	= 0x00007edcba987000UL,
		}
	},
};

/* VM-entry-load and VM-exit-load, each 0 or 1. There are 4 combinations in total. */
#define NR_CTRL_COMBOS		4
/* each load control combination includes 2 cases with different VM-exit reasons. */
#define NR_CASES		(NR_CTRL_COMBOS * 2)

/* core function: define what state the hardware should retain in different cases. */
static enum state_src get_expected_state_src(bool entry_load, bool exit_load,
					     uint32_t exit_reason)
{
	if (exit_load)
		return STATE_SRC_VMCS12_HOST;

	/* no entry load, no exit load - L1's own state is retained. */
	if (!entry_load)
		return STATE_SRC_L1;

	/*
	 * From the Intel SDM volume 3, chapter 29.3 "CHECKING AND LOADING
	 * GUEST STATE":
	 *   The following operations take place concurrently:
	 *     (1) the guest-state area of the VMCS is checked to ensure that,
	 *         after the VM entry completes, the state of the logical
	 *         processor is consistent with IA-32 and Intel 64
	 *         architectures;
	 *     (2) processor state is loaded from the guest-state area or as
	 *         specified by the VM-entry control fields;
	 *     and (3) address-range monitoring is cleared.
	 *   Because the checking and the loading occur concurrently, a failure
	 *   may be discovered only after some state has been loaded.
	 *
	 * KVM's emulation of nested case checks the guest state first and then
	 * load it, which matches SDM. Based on this, the guest state checking
	 * failure should retain L1's own state.
	 */
	if (exit_reason == EXIT_REASON_INVALID_STATE)
		return STATE_SRC_L1;

	return STATE_SRC_VMCS12_GUEST;
}

static void l1_load_own_state(void)
{
	if (has_shstk) {
		const struct cet_state *cet = &states[STATE_SRC_L1].cet;

		wrmsr(MSR_IA32_S_CET, cet->s_cet);
		wrmsr(MSR_IA32_INT_SSP_TAB, cet->ssp_tbl);
	}
}

static void l1_program_vmcs12_cet(bool entry_load, bool exit_load)
{
	const struct cet_state *guest = &states[STATE_SRC_VMCS12_GUEST].cet;
	const struct cet_state *host = &states[STATE_SRC_VMCS12_HOST].cet;
	uint64_t entry_ctrl = vmreadz(VM_ENTRY_CONTROLS) & ~VM_ENTRY_LOAD_CET_STATE;
	uint64_t exit_ctrl = vmreadz(VM_EXIT_CONTROLS) & ~VM_EXIT_LOAD_CET_STATE;

	GUEST_ASSERT(!vmwrite(GUEST_S_CET, guest->s_cet));
	GUEST_ASSERT(!vmwrite(GUEST_SSP, guest->ssp));
	GUEST_ASSERT(!vmwrite(GUEST_INTR_SSP_TABLE, guest->ssp_tbl));
	GUEST_ASSERT(!vmwrite(HOST_S_CET, host->s_cet));
	GUEST_ASSERT(!vmwrite(HOST_SSP, host->ssp));
	GUEST_ASSERT(!vmwrite(HOST_INTR_SSP_TABLE, host->ssp_tbl));

	if (entry_load)
		entry_ctrl |= VM_ENTRY_LOAD_CET_STATE;
	if (exit_load)
		exit_ctrl |= VM_EXIT_LOAD_CET_STATE;

	GUEST_ASSERT(!vmwrite(VM_ENTRY_CONTROLS, entry_ctrl));
	GUEST_ASSERT(!vmwrite(VM_EXIT_CONTROLS, exit_ctrl));
}

static void l1_program_vmcs12_state(bool entry_load, bool exit_load)
{
	if (has_shstk)
		l1_program_vmcs12_cet(entry_load, exit_load);
}

/*
 * Set the invalid guest state to fail the VM-entry check
 * — triggering a VM-exit (EXIT_REASON_INVALID_STATE).
 */
static void l1_break_guest_state(void)
{
	uint64_t cr0 = vmreadz(GUEST_CR0);

	GUEST_ASSERT(!vmwrite(GUEST_CR0, (cr0 | X86_CR0_PG) & ~X86_CR0_PE));
}

/*
 * Set the invalid MSR load list to fail the VM-entry check
 * — triggering a VM-exit (EXIT_REASON_MSR_LOAD_FAIL).
 */
static void l1_break_msr_load_list(void)
{
	struct vmx_msr_entry *list = (void *)entry_msr_load_list_gva;

	list[0] = (struct vmx_msr_entry){
		.index = MSR_IA32_UCODE_REV,
		.reserved = 0,
		.value = 0,
	};

	GUEST_ASSERT(!vmwrite(VM_ENTRY_MSR_LOAD_ADDR, entry_msr_load_list_gpa));
	GUEST_ASSERT(!vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 1));
}

static void l1_check_observed_cet(bool entry_load, bool exit_load, uint32_t exit_reason)
{
	enum state_src src = get_expected_state_src(entry_load, exit_load, exit_reason);
	const struct cet_state *expect = &states[src].cet;
	uint64_t s_cet = rdmsr(MSR_IA32_S_CET);
	uint64_t ssp_tbl = rdmsr(MSR_IA32_INT_SSP_TAB);

	__GUEST_ASSERT(s_cet == expect->s_cet && ssp_tbl == expect->ssp_tbl,
		       "entry_load=%d exit_load=%d exit_reason=%u: "
		       "expect src %d S_CET=%#lx INT_SSP_TAB=%#lx, "
		       "got S_CET=%#lx INT_SSP_TAB=%#lx",
		       entry_load, exit_load, exit_reason, src, expect->s_cet,
		       expect->ssp_tbl, s_cet, ssp_tbl);
}

static void l1_check_observed_state(bool entry_load, bool exit_load, uint32_t exit_reason)
{
	if (has_shstk)
		l1_check_observed_cet(entry_load, exit_load, exit_reason);
}

static void l1_run_case(struct vmx_pages *vmx, bool entry_load, bool exit_load,
			uint32_t exit_reason)
{
	l1_load_own_state();

	GUEST_ASSERT(load_vmcs(vmx));
	prepare_vmcs(vmx, NULL, NULL);

	l1_program_vmcs12_state(entry_load, exit_load);

	switch (exit_reason) {
	case EXIT_REASON_INVALID_STATE:
		l1_break_guest_state();
		break;
	case EXIT_REASON_MSR_LOAD_FAIL:
		l1_break_msr_load_list();
		break;
	default:
		GUEST_FAIL("unexpected exit reason %u", exit_reason);
	}

	GUEST_ASSERT(!vmlaunch());
	GUEST_ASSERT_EQ(vmreadz(VM_EXIT_REASON),
			EXIT_REASON_FAILED_VMENTRY | exit_reason);

	l1_check_observed_state(entry_load, exit_load, exit_reason);

	GUEST_SYNC(0);
}

static void l1_guest_code(struct vmx_pages *vmx)
{
	int ctrl;

	GUEST_ASSERT(prepare_for_vmx_operation(vmx));

	for (ctrl = 0; ctrl < NR_CTRL_COMBOS; ctrl++) {
		bool entry_load = ctrl & 1;
		bool exit_load = ctrl & 2;

		/* 2 cases with different VM-exit reasons. */
		l1_run_case(vmx, entry_load, exit_load, EXIT_REASON_INVALID_STATE);
		l1_run_case(vmx, entry_load, exit_load, EXIT_REASON_MSR_LOAD_FAIL);
	}

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	gva_t vmx_pages_gva;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	int ncases = 0;

	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_VMX));

	has_shstk = kvm_cpu_has(X86_FEATURE_SHSTK);
	TEST_REQUIRE(has_shstk);

	vm = vm_create_with_one_vcpu(&vcpu, l1_guest_code);

	entry_msr_load_list_gva = vm_alloc_page(vm);
	entry_msr_load_list_gpa = addr_gva2gpa(vm, entry_msr_load_list_gva);
	sync_global_to_guest(vm, entry_msr_load_list_gva);
	sync_global_to_guest(vm, entry_msr_load_list_gpa);

	sync_global_to_guest(vm, has_shstk);

	vcpu_alloc_vmx(vm, &vmx_pages_gva);
	vcpu_args_set(vcpu, 1, vmx_pages_gva);

	for (;;) {
		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			ncases++;
			break;
		case UCALL_DONE:
			TEST_ASSERT(ncases == NR_CASES, "L1 ran %d cases, expected %d",
				    ncases, NR_CASES);
			goto done;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
		}
	}
done:
	kvm_vm_free(vm);
	return 0;
}
