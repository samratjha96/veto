// Supply chain attack detection rules.
//
// Detects: suspicious package installs, typosquatting indicators,
// install from untrusted sources, post-install script abuse,
// dependency confusion, and package publishing.

rule supply_chain_pip_install_url
{
    meta:
        description = "pip install from URL or VCS — bypasses registry vetting"
        category    = "supply_chain"
        severity    = "high"

    strings:
        $pip_url    = /pip3?\s+install\s+[^\s]*https?:\/\// nocase
        $pip_git    = /pip3?\s+install\s+git\+/ nocase
        $pip_svn    = /pip3?\s+install\s+svn\+/ nocase
        $uv_url     = /uv\s+pip\s+install\s+[^\s]*https?:\/\// nocase
        $uv_git     = /uv\s+pip\s+install\s+git\+/ nocase

    condition:
        any of them
}

rule supply_chain_npm_install_url
{
    meta:
        description = "npm/yarn install from tarball URL or git — bypasses registry"
        category    = "supply_chain"
        severity    = "high"

    strings:
        $npm_url    = /npm\s+install\s+https?:\/\// nocase
        $npm_git    = /npm\s+install\s+git[+:]/ nocase
        $yarn_url   = /yarn\s+add\s+https?:\/\// nocase
        $yarn_git   = /yarn\s+add\s+git[+:]/ nocase
        $pnpm_url   = /pnpm\s+(add|install)\s+https?:\/\// nocase

    condition:
        any of them
}

rule supply_chain_cargo_install_git
{
    meta:
        description = "cargo install from git — bypasses crates.io"
        category    = "supply_chain"
        severity    = "medium"

    strings:
        $cargo_git = /cargo\s+install\s+--git\s/ nocase

    condition:
        any of them
}

rule supply_chain_npm_publish
{
    meta:
        description = "npm/cargo publish — publishes a package to a registry"
        category    = "supply_chain"
        severity    = "high"

    strings:
        $npm_publish   = /npm\s+publish/ nocase
        $yarn_publish  = /yarn\s+publish/ nocase
        $cargo_publish = /cargo\s+publish/ nocase
        $twine_upload  = /twine\s+upload/ nocase
        $gem_push      = /gem\s+push/ nocase

    condition:
        any of them
}

rule supply_chain_preinstall_script
{
    meta:
        description = "Package preinstall/postinstall script patterns"
        category    = "supply_chain"
        severity    = "high"

    strings:
        $preinstall  = "\"preinstall\"" nocase
        $postinstall = "\"postinstall\"" nocase
        $install     = "\"install\"" nocase
        // Dangerous patterns in scripts
        $eval_require = /require\s*\(\s*['"]child_process['"]\s*\)/
        $exec_sync   = "execSync(" nocase

    condition:
        ($preinstall or $postinstall or $install) and ($eval_require or $exec_sync)
}

rule supply_chain_pip_install_no_verify
{
    meta:
        description = "pip install with disabled verification"
        category    = "supply_chain"
        severity    = "high"

    strings:
        $no_deps    = /pip3?\s+install\s+.*--no-deps/ nocase
        $trusted    = /pip3?\s+install\s+.*--trusted-host/ nocase
        $extra_idx  = /pip3?\s+install\s+.*--extra-index-url/ nocase

    condition:
        any of them
}

rule supply_chain_global_install
{
    meta:
        description = "Global package install — modifies system-wide packages"
        category    = "supply_chain"
        severity    = "medium"

    strings:
        $npm_g      = /npm\s+install\s+-g\s/ nocase
        $npm_global = /npm\s+install\s+--global\s/ nocase
        $pip_sudo   = /sudo\s+pip3?\s+install/ nocase
        $gem_sudo   = /sudo\s+gem\s+install/ nocase

    condition:
        any of them
}

rule supply_chain_setup_py_exec
{
    meta:
        description = "setup.py with code execution — common supply chain vector"
        category    = "supply_chain"
        severity    = "high"

    strings:
        $setup_py   = "setup.py"
        $python_run = /python3?\s+setup\.py\s+install/ nocase
        $os_system  = "os.system(" nocase
        $subprocess = "subprocess.call(" nocase
        $exec_fn    = /\bexec\s*\(/ nocase

    condition:
        $setup_py and ($os_system or $subprocess or $exec_fn or $python_run)
}

rule supply_chain_registry_override
{
    meta:
        description = "Package registry override — potential dependency confusion"
        category    = "supply_chain"
        severity    = "medium"

    strings:
        $cargo_reg   = /\[registries\./ nocase
        $pip_extra   = /extra-index-url\s*=/ nocase

    condition:
        any of them
}
