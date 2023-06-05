/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell
 */

def run_ci(Object s) {
	node ("buildenv-2004-le") {
		s.GROOVY_DIR = '/data/isoc_platform_devops/dev-ci/scripts_cache/dev-ci/dpu-offload'
		s.preinit = load s.GROOVY_DIR + "/preinit.groovy"
	}
	s.preinit.run(s)
}

return this
