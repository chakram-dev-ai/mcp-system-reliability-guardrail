<#
.SYNOPSIS
    Enables the Windows ground-truth sources guardrail-monitor depends on.

.DESCRIPTION
    Run elevated. Read it before you run it -- it changes audit policy
    machine-wide.

    Every precondition is checked BEFORE anything is changed, and the script
    stops with "Nothing was changed" if one fails. Run it with -ValidateOnly
    first: that needs no elevation and changes nothing.

    Each block below is independent; comment out what you do not want.

.EXAMPLE
    .\collectors\setup-windows.ps1 -AgentAccount "HOST\agent" -ValidateOnly

.EXAMPLE
    .\collectors\setup-windows.ps1 -AgentAccount "HOST\agent" -SysmonPath C:\Tools\Sysmon\sysmon64.exe
#>

[CmdletBinding()]
param(
    # The account the AGENT runs as. Must exist, and must not be the account
    # the monitor runs as: block 6 denies it all access to the log.
    [Parameter(Mandatory = $true)]
    [string]$AgentAccount,

    # Defaults to the agent's real profile directory, read from the registry.
    [string]$AgentProfile = "",

    # Must match `workspace` and `canary_dir` in policy.windows.yaml; checked.
    # Default to <profile>\project and <profile>\.gm-canaries.
    [string]$Workspace = "",
    [string]$CanaryDir = "",

    [string]$LogDir = "$env:ProgramData\gm",

    # The account gm.monitor runs as, if not SYSTEM / an administrator.
    [string]$MonitorAccount = "",

    # An account that runs gm.server (the MCP query process) without being an
    # administrator: granted read on the log directory, nothing else.
    [string]$ReaderAccount = "",

    [string]$SysmonPath = "",

    # Default to the files that ship next to this script, not to paths
    # relative to whatever directory it happens to be run from.
    [string]$SysmonConfig = "",
    [string]$PolicyPath = "",

    # Sysmon is already installed and configured; leave it alone.
    [switch]$SkipSysmon,

    # Run the checks, print the plan, change nothing.
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
# $PSScriptRoot is empty inside a param() default on Windows PowerShell 5.1.
if (-not $SysmonConfig) { $SysmonConfig = Join-Path $PSScriptRoot "sysmon-config.xml" }
if (-not $PolicyPath) { $PolicyPath = Join-Path (Split-Path $PSScriptRoot -Parent) "policy.windows.yaml" }
$problems = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Resolve-Sid([string]$Account) {
    try {
        $nt = New-Object System.Security.Principal.NTAccount($Account)
        return $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Test-SamePath([string]$A, [string]$B) {
    return ($A.TrimEnd('\', '/') -ieq $B.TrimEnd('\', '/'))
}

function Get-PolicyVar([string]$Path, [string]$Name) {
    $pattern = '^\s*' + [regex]::Escape($Name) + ':\s*(.+?)\s*$'
    $m = Select-String -Path $Path -Pattern $pattern | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value.Trim('"', "'") }
    return $null
}

# =============================================================================
# Preflight. Nothing below this line changes the machine until it passes.
# =============================================================================

# --- the agent account, and where its profile really is ----------------------
$agentSid = Resolve-Sid $AgentAccount
if (-not $agentSid) {
    $problems.Add("AgentAccount '$AgentAccount' does not resolve to an account. Create it first (New-LocalUser): block 6 cannot deny access to an account that does not exist, and it used to fail there -- after blocks 1-5 had already changed the machine.")
}

# The old script hardcoded C:\Users\agent\... for the credential-store SACLs,
# whatever -AgentAccount said. Any other profile name was silently skipped and
# cred.read could never fire.
if (-not $AgentProfile -and $agentSid) {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$agentSid"
    if (Test-Path $key) {
        $AgentProfile = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty $key).ProfileImagePath)
    }
}
if (-not $AgentProfile) {
    $leaf = ($AgentAccount -split '\\')[-1]
    $AgentProfile = Join-Path "$env:SystemDrive\Users" $leaf
    $warnings.Add("No profile found for '$AgentAccount' (has it ever signed in?). Assuming $AgentProfile. Credential stores that do not exist are skipped: sign in as the agent once, then re-run.")
}
if (-not $Workspace) { $Workspace = Join-Path $AgentProfile "project" }
if (-not $CanaryDir) { $CanaryDir = Join-Path $AgentProfile ".gm-canaries" }

# --- the monitor must not be the agent ---------------------------------------
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($agentSid) {
    if ($MonitorAccount) {
        $monitorSid = Resolve-Sid $MonitorAccount
        if (-not $monitorSid) {
            $problems.Add("MonitorAccount '$MonitorAccount' does not resolve to an account.")
        } elseif ($monitorSid -eq $agentSid) {
            $problems.Add("MonitorAccount is the agent account. Block 6 denies the agent account all access to $LogDir, so a monitor running as it could not write its own log. Run the agent under a separate account.")
        }
    } elseif ($me.User.Value -eq $agentSid) {
        $problems.Add("You are running this as the agent account ($AgentAccount) with no -MonitorAccount, so the monitor would run as this account too. Block 6 denies the agent account all access to $LogDir -- a Deny ACE applies elevated or not -- and the monitor could not write its own log. Run the agent under a separate account.")
    }
    if ($ReaderAccount) {
        $readerSid = Resolve-Sid $ReaderAccount
        if (-not $readerSid) {
            $problems.Add("ReaderAccount '$ReaderAccount' does not resolve to an account.")
        } elseif ($readerSid -eq $agentSid) {
            $problems.Add("ReaderAccount is the agent account. The agent must not be able to read its own audit trail.")
        }
    }
}

# --- Sysmon ------------------------------------------------------------------
if (-not $SkipSysmon) {
    if ($SysmonPath) {
        if (-not (Test-Path $SysmonPath -PathType Leaf)) {
            $problems.Add("SysmonPath '$SysmonPath' does not exist.")
        }
    } else {
        $cmd = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
        if ($cmd) {
            $SysmonPath = $cmd.Source
        } else {
            $problems.Add("sysmon64.exe is not on PATH. Download Sysmon from Sysinternals and pass -SysmonPath, or pass -SkipSysmon if it is already installed and configured.")
        }
    }
    if (-not (Test-Path $SysmonConfig -PathType Leaf)) {
        $problems.Add("Sysmon config not found at $SysmonConfig.")
    }
}

# --- the policy must agree with the SACLs this script sets --------------------
if (Test-Path $PolicyPath -PathType Leaf) {
    foreach ($pair in @(@("workspace", $Workspace), @("canary_dir", $CanaryDir))) {
        $value = Get-PolicyVar $PolicyPath $pair[0]
        if ($value -and -not (Test-SamePath $value $pair[1])) {
            $warnings.Add("$PolicyPath has $($pair[0]): $value, but this run uses $($pair[1]). The rules and the SACLs will disagree and the probes will FAIL; edit one of them.")
        }
    }
} else {
    $warnings.Add("Policy file not found at $PolicyPath; workspace and canary_dir were not cross-checked.")
}

# --- elevation ---------------------------------------------------------------
$isAdmin = (New-Object System.Security.Principal.WindowsPrincipal $me).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $ValidateOnly -and -not $isAdmin) {
    $problems.Add("Not elevated. Run from an elevated PowerShell, or use -ValidateOnly, which changes nothing.")
}

Write-Host "guardrail-monitor Windows setup -- preflight"
Write-Host ("  agent account   {0} ({1})" -f $AgentAccount, $agentSid)
Write-Host ("  agent profile   {0}" -f $AgentProfile)
Write-Host ("  workspace       {0}" -f $Workspace)
Write-Host ("  canary dir      {0}" -f $CanaryDir)
Write-Host ("  log dir         {0}" -f $LogDir)
Write-Host ("  monitor account {0}" -f $(if ($MonitorAccount) { $MonitorAccount } else { "SYSTEM / Administrators" }))
Write-Host ("  reader account  {0}" -f $(if ($ReaderAccount) { $ReaderAccount } else { "(none)" }))
Write-Host ("  sysmon          {0}" -f $(if ($SkipSysmon) { "skipped" } else { $SysmonPath }))
foreach ($w in $warnings) { Write-Warning $w }
if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Host "PROBLEM: $p" }
    Write-Host "`nNothing was changed."
    exit 1
}
if ($ValidateOnly) {
    Write-Host "`nPreflight passed. Nothing was changed (-ValidateOnly)."
    exit 0
}

# =============================================================================
# Changes
# =============================================================================

# --- 1. Sysmon: exec, network, DNS, file create, registry --------------------
if (-not $SkipSysmon) {
    if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
        & $SysmonPath -accepteula -i $SysmonConfig
    } else {
        & $SysmonPath -c $SysmonConfig
    }
}

# --- 2. PowerShell script block logging (Event 4104) -------------------------
# Gives you deobfuscated script text. There is no Linux equivalent and it is
# the single highest-value source on this platform.
$pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $pol -Force | Out-Null
Set-ItemProperty -Path $pol -Name EnableScriptBlockLogging -Value 1 -Type DWord

# --- 3. Object access auditing (Event 4663) ----------------------------------
# The ONLY practical route to file-READ visibility on Windows. Sysmon has no
# file-read event, so without this the cred.read rule is dead code.
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null

# --- 4. SACLs on the credential stores ---------------------------------------
# Scope these tightly. A SACL on a busy directory will bury the Security log.
$watched = @(
    (Join-Path $AgentProfile ".ssh"),
    (Join-Path $AgentProfile ".aws"),
    (Join-Path $AgentProfile "AppData\Roaming\Microsoft\Protect"),
    # Canary directories. Without a SACL here canary.file can never fire, and a
    # probe suite that always reports FAIL is indistinguishable from a control
    # that is genuinely dead -- the one thing DESIGN.md 6.2 says you must be
    # able to tell apart. Created if absent, unlike the credential stores
    # above: an empty canary dir on a fresh host is normal, an absent ~/.ssh is
    # a reason to skip.
    $CanaryDir,
    "$CanaryDir-escape"
)
foreach ($dir in $watched) {
    if (-not (Test-Path $dir)) {
        if ($dir -like "$CanaryDir*") {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "created: $dir"
        } else {
            Write-Warning "skip (absent): $dir"; continue
        }
    }
    $acl  = Get-Acl -Path $dir -Audit
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "ReadData,WriteData,AppendData",
        "ContainerInherit,ObjectInherit",
        "None",
        "Success"
    )
    $acl.AddAuditRule($rule)
    Set-Acl -Path $dir -AclObject $acl
    Write-Host "SACL set: $dir"
}

# --- 5. Raise the Security log size ------------------------------------------
# 4663 is high volume. The default 20MB will roll in minutes and you will lose
# exactly the events you built this to catch.
wevtutil sl Security /ms:1073741824
if (-not $SkipSysmon) {
    wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
}

# --- 6. Deny the agent account read access to the monitor's log --------------
# The agent can append events through the named pipe. It must not be able to
# read, enumerate, or delete what has already been written.
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$acl = Get-Acl $LogDir
$acl.SetAccessRuleProtection($true, $false)   # break inheritance
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))

# A monitor under its own non-admin account needs to write the log it exists
# to produce. Modify, not FullControl: it must not be able to rewrite the ACL
# on its own evidence.
if ($MonitorAccount) {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $MonitorAccount,"Modify","ContainerInherit,ObjectInherit","None","Allow")))
} else {
    Write-Warning "No -MonitorAccount given: only SYSTEM and Administrators can write $LogDir. Run gm.monitor elevated or as SYSTEM, or pass -MonitorAccount."
}

# The MCP query process only reads: events, alerts, status. (run_probe_suite
# reports, rather than fails, when it cannot record its probe.start markers.)
if ($ReaderAccount) {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $ReaderAccount,"ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")))
}

# Deny last, and explicitly: a Deny ACE outranks any Allow the agent might
# otherwise inherit or be granted by group membership.
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $AgentAccount,"FullControl","ContainerInherit,ObjectInherit","None","Deny")))
Set-Acl $LogDir $acl
Write-Host "ACL set: $LogDir (agent denied)"

Write-Host "`nDone. Next: start gm.monitor, then run the probe suite from the supervisor -- do not assume any of the above worked."
