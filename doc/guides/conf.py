# SPDX-License-Identifier: Marvell-MIT

from datetime import datetime

project   = "Data Accelerator Offload"
author    = "Marvell"
release   = "25.05.0"  # display-only; SMV controls per-version output
copyright = f"2024-{datetime.now().year}, Marvell"

html_logo = "logo/dao_logo.png"
master_doc = "index"

extensions = [
    "sphinx_copybutton",
    "sphinx_multiversion",
    "sphinx_design",
]

# Build policy for SMV
smv_remote_whitelist = r"^origin$"
smv_branch_whitelist = r"^(dao\-.*|dao\-devel)$"
smv_tag_whitelist    = r"^$"
smv_outputdir_format = "{ref.name}"

# Current branch name
version = "dao-devel"

html_theme = "pydata_sphinx_theme"

html_theme_options = {
    "switcher": {
        "json_url": "https://marvellembeddedprocessors.github.io/dao/guides/versions.json",
        "version_match": version,
    },
    "navbar_end": [
        "search-button",
        "version-switcher",
        "navbar-icon-links",
    ],
    "icon_links": [
        {
            "name": "GitHub Repo",
            "url": "https://github.com/MarvellEmbeddedProcessors/dao.git",
            "icon": "fa-brands fa-github",
            "type": "fontawesome",
        },
    ],
}

# Pin to light mode
html_meta = {"color-scheme": "light"}

html_static_path = ["_static"]
html_css_files   = ["css/custom.css"]
html_js_files    = [
    "js/version_switcher_match.js",  # keeps button label synced with URL
]

html_favicon       = "_static/tab_logo.jpg"
html_show_sourcelink = False

# Remove sidebars on landing
html_sidebars = {"index": []}

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
templates_path   = ["_templates"]