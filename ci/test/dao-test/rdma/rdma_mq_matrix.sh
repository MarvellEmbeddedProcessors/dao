#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2026 Marvell.
#

MQ_TEST_MATRIX=(
	"UD_SEND_Host_Server|Test 1: UD SEND - Host Server -> Remote Client|UD|SEND|100|8|1000|1024|||"
	"RC_SEND_Host_Server|Test 2: RC SEND - Host Server -> Remote Client|RC|SEND|100|8|1000|1024|||"
	"RC_WRITE_Host_Server|Test 3: RC WRITE - Host Server -> Remote Client|RC|WRITE|100|8|1000|1024|||"
	"RC_WRITE_IMM_Host_Server|Test 4: RC WRITE_IMM - Host Server -> Remote Client|RC|WRITE_IMM|100|8|1000|1024|||"
	"RC_READ_Host_Server|Test 5: RC READ - Host Server -> Remote Client|RC|READ|100|8|1000|1024|||"
	"UD_SEND_SGE_Host_Server|Test 6: UD SEND SGE=2 - Host Server -> Remote Client|UD|SEND|100|8|1000|1024|2||"
	"RC_SEND_SGE_Host_Server|Test 7: RC SEND SGE=2 - Host Server -> Remote Client|RC|SEND|100|8|1000|1024|2||"
	"RC_WRITE_SGE_Host_Server|Test 8: RC WRITE SGE=2 - Host Server -> Remote Client|RC|WRITE|100|8|1000|1024|2||"
	"RC_WRITE_IMM_SGE_Host_Server|Test 9: RC WRITE_IMM SGE=2 - Host Server -> Remote Client|RC|WRITE_IMM|100|8|1000|1024|2||"
	"RC_READ_SGE_Host_Server|Test 10: RC READ SGE=2 - Host Server -> Remote Client|RC|READ|100|8|1000|1024|2||"
	"Repeated_RC_SEND_Host_Server|Test 12: Repeated Connect RC SEND - Host Server (1000 conn)|RC|SEND|1|1|1000|1024||1000|1000"
	"Repeated_RC_WRITE_Host_Server|Test 13: Repeated Connect RC WRITE - Host Server (1000 conn)|RC|WRITE|1|1|1000|1024||1000|1000"
	"Repeated_RC_WRITE_IMM_Host_Server|Test 14: Repeated Connect RC WRITE_IMM - Host Server (1000 conn)|RC|WRITE_IMM|1|1|1000|1024||1000|1000"
	"Repeated_RC_READ_Host_Server|Test 15: Repeated Connect RC READ - Host Server (1000 conn)|RC|READ|1|1|1000|1024||1000|1000"
	"Repeated_RC_SEND_SGE_Host_Server|Test 17: Repeated Connect RC SEND SGE=2 - Host Server|RC|SEND|1|1|1000|1024|2|1000|1000"
	"Repeated_RC_WRITE_SGE_Host_Server|Test 18: Repeated Connect RC WRITE SGE=2 - Host Server|RC|WRITE|1|1|1000|1024|2|1000|1000"
	"Repeated_RC_WRITE_IMM_SGE_Host_Server|Test 19: Repeated Connect RC WRITE_IMM SGE=2 - Host Server|RC|WRITE_IMM|1|1|1000|1024|2|1000|1000"
	"Repeated_RC_READ_SGE_Host_Server|Test 20: Repeated Connect RC READ SGE=2 - Host Server|RC|READ|1|1|1000|1024|2|1000|1000"
)

function rdma_mq_run_matrix()
{
	local row name banner qp_type op num_qp threads iter size nb_sge loop_count server_max

	for row in "${MQ_TEST_MATRIX[@]}"; do
		IFS='|' read -r name banner qp_type op num_qp threads iter size nb_sge loop_count server_max <<< "$row"
		mq_banner "$banner"
		run_mq_test "$name" "$qp_type" "$op" "$num_qp" "$threads" "$iter" "$size" \
			"${nb_sge:-}" "${loop_count:-}" "${server_max:-}" || true
		echo ""
	done
}
