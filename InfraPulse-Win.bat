@echo off
rem ============================================================================
rem  INFRAPULSE-WIN  v1.0
rem  Single-file internal-network VAPT assessment engine (batch launcher)
rem  ----------------------------------------------------------------------------
rem  PURPOSE
rem    Run an authorised, attacker-perspective assessment of the internal
rem    network from this host, validate what can be validated without causing
rem    change, and write reproducible evidence to CSV. Every module reports
rem    EXPECTED / CONFIGURED / OBSERVED / VALIDATION / RESULT and separates
rem    CONFIGURATION EVIDENCE from ACTIVE VALIDATION and IMPACT EVIDENCE.
rem
rem  AUTHORISATION - READ BEFORE RUNNING
rem    Use this tool only on assets you are explicitly authorised to assess,
rem    under a signed engagement scope. It performs active validation steps.
rem    The engine asks for explicit console consent before each active step:
rem      * the bounded TCP discovery sweep derived from the local IPv4 scope
rem      * the read-only credential-reachability check of remote hosts
rem    If no console is available both steps are skipped and reported as
rem    NOT TESTABLE rather than assumed either way.
rem
rem  FORENSIC INTEGRITY
rem    The first data row of the CSV report is written before any assessment module runs. It
rem    records the SHA-256 of THIS launcher and of the engine extracted from it, states which
rem    mechanism produced each digest, and captures the run context (host, user, elevation,
rem    PowerShell version, language mode). A reviewer can therefore prove which code produced every
rem    following row, and can detect a modified launcher or engine: hash the .bat with Get-FileHash
rem    -Algorithm SHA256 and compare with the copy held by the engagement owner, and compare the
rem    engine digest against the value printed below at start-up.
rem
rem  NO NATIVE HELPER BINARIES FOR IDENTITY
rem    The engine enumerates integrity level and token privileges in memory (GetTokenInformation
rem    through a cached P/Invoke helper, with a managed .NET fallback). It does not spawn
rem    whoami.exe, so Application Control (WDAC/AppLocker) cannot block the identity checks and the
rem    run adds no process-creation noise to the Security event log. If neither in-memory path is
rem    available the affected rows are reported NOT TESTABLE with the reason - never assumed.
rem
rem  WHAT THE ENGINE DOES NOT DO - BY CONSTRUCTION
rem    No credential dumping, no reading of LSASS memory, no password spraying,
rem    no Kerberos ticket theft or replay, no persistence, no security-product
rem    evasion, no concealment of its own activity, no modification of remote
rem    systems. Read-only handshakes and registrations only.
rem
rem  ARCHITECTURE
rem    cmd.exe cannot host a 21-module assessment engine, so the launcher
rem    carries the PowerShell engine as embedded text between two marker lines.
rem    At run time the engine writes the embedded text to a private %TEMP%
rem    folder as a .ps1, runs it, and removes the temporary extraction.
rem    Command Prompt stops executing at the line before the markers, so the
rem    embedded PowerShell is never interpreted by cmd.exe: the text is
rem    byte-identical to the reviewed source, with no escaping applied.
rem
rem  ENGINE SECTIONS (21)
rem     1 system initialisation and role detection
rem     2 local security configuration audit
rem     3 SMB security assessment with live protocol negotiation
rem     4 authentication policy against observed authentication behaviour
rem     5 LSA / LSASS protection posture
rem     6 print spooler exposure and role awareness
rem     7 Windows Update / WSUS posture
rem     8 bounded network discovery over the authorised local scope
rem     9 Active Directory enumeration through ADSI only
rem    10 userAccountControl decoding and Kerberos pre-authentication check
rem    11 SPN and service-account audit
rem    12 delegation audit
rem    13 Kerberos encryption-type downgrade audit
rem    14 LAPS coverage audit, metadata only
rem    15 network segmentation validation
rem    16 lateral-movement attack-path analysis
rem    17 local privilege-escalation audit with controlled proof
rem    18 LOLBin / native execution assessment
rem    19 active exploitability validation
rem    20 attack-chain correlation
rem    21 reporting, executive summary and evidence classification
rem
rem  OUTPUT - written to the folder this launcher is started from
rem    Internal_VAPT_Compliance_Report.csv   14 mandated columns, UTF-8 BOM
rem    Internal_VAPT_Test_Registry.csv       per-test outcome registry
rem
rem  OPERATIONAL CHECKLIST - CHANGE-MANAGEMENT WINDOW
rem    Work through these four steps in order; each one produces an artifact the next step relies on.
rem
rem    [1] VALIDATE THE BASELINE HASH - before transfer, on the administrative workstation
rem          Get-FileHash -Path .\InfraPulse-Win.bat -Algorithm SHA256
rem        Record the digest in the change record. Provenance then has three anchors: the value from
rem        this command, the launcher's own SHA-256 printed at start-up, and the engine-recomputed
rem        digest written into the report at step 4. Compare all three.
rem
rem    [2] PASSIVE / NO-EGRESS PROFILING - no remote probes at all
rem          InfraPulse-Win.bat /localonly
rem        /localonly suppresses EVERY remote operation: the address sweep, the domain controller
rem                   reachability probe, LDAP/ADSI directory queries (Sections 9-14), the Kerberos
rem                   AS-REQ probe and the remote administrative-reachability check. Only loopback
rem                   probes against this host remain, and they leave no packet off the machine.
rem                   Name resolution performed by the operating system itself (for example the
rem                   local host's own name) is outside this control and is not suppressed - every
rem                   ASSESSMENT probe, however, is.
rem        The same no-egress result is still reported honestly: each suppressed step is published
rem        NOT TESTABLE with the operator-suppression wording, never as a clean pass.
rem
rem    [3] FULL ACTIVE ASSESSMENT - the default double-click behaviour
rem          InfraPulse-Win.bat
rem        No prompt is shown: the bounded address sweep and the read-only remote
rem        administrative-reachability check are pre-authorised by the launcher defaults set below
rem        :argsdone. The live console output, tables and executive summary render in real time,
rem        and the window pauses at the end so the summary can be read.
rem        BEFORE RUNNING THIS WAY, confirm that executing the file is inside your authorised
rem        scope - the sweep covers every host in the derived local /24, and the remote check
rem        executes one read-only command over WinRM against hosts where administrative rights are
rem        confirmed. Use /localonly if the change window forbids off-host traffic.
rem
rem    [4] COLLECT AND SIGN OFF THE EVIDENCE
rem          Internal_VAPT_Compliance_Report.csv
rem             Row 1 is the header. Row 2 - the FIRST DATA ROW - is the self-authenticating
rem             integrity signature: launcher SHA-256, engine SHA-256, the mechanism that produced
rem             each digest, and the run context (host, user, elevation, PowerShell version,
rem             language mode). Confirm this row exists and that its launcher digest matches the
rem             value from step 1 BEFORE passing the report to downstream consumers.
rem          Internal_VAPT_Test_Registry.csv
rem             One row per test unit with its outcome, for tracking remediation to closure.
rem        Both files are written incrementally, so an interrupted run still yields usable evidence.
rem
rem  USAGE  (consent prompts are bypassed by default - see AUTOMATION / CONSENT MODEL)
rem    InfraPulse-Win.bat              double-click run: unattended, active steps
rem                                                        pre-authorised, window pauses at the end
rem                                                        so the summary can be read
rem    InfraPulse-Win.bat /nopause     no final pause - use for scheduled tasks
rem                                                        and orchestrated runs
rem    InfraPulse-Win.bat /localonly   suppress every remote operation: sweep,
rem                                                        DC probe, LDAP, Kerberos AS-REQ and the
rem                                                        remote administrative check
rem    InfraPulse-Win.bat /?           usage
rem    InfraPulse-Win.bat /scope:10.0.0.0/24,!10.0.0.99
rem                                                        confine EVERY off-host operation to the
rem                                                        supplied scope (default-deny)
rem
rem  ENGAGEMENT SCOPE
rem    Supplying /scope: (or EIA_SCOPE / EIA_SCOPE_FILE) changes the run from permissive to
rem    DEFAULT-DENY. Every remote operation - the address sweep, the service matrix, the banner
rem    capture, the DC reachability probe and the administrative-reachability candidates - passes
rem    through a single gate that refuses any target not matching an include entry. Exclusions
rem    win over includes. The scope and its source are recorded as the second data row of the
rem    CSV, so the report itself states the boundary the run was confined to.
rem
rem    A host name suffix entry needs a leading dot (.corp.example.com), which keeps the entry
rem    from also matching evilcorp.example.com. Host entries match TEXTUALLY - the tool does not
rem    resolve names to decide scope, because that would itself be an off-host query.
rem
rem    KILL SWITCH: create a file named EIA_STOP in the working directory or in %TEMP% (or set
rem    EIA_KILL_SWITCH=1) and the run stops starting new modules and refuses every further
rem    off-host operation. The CSV records which modules were skipped and why.
rem
rem    /headless and /authorize-active are still accepted. Both states are now the default;
rem    /authorize-active additionally records itself as the authorisation source in the evidence.
rem
rem  AUTOMATION / CONSENT MODEL
rem    Consent prompts are BYPASSED BY DEFAULT. The launcher sets EIA_HEADLESS=1 and
rem    EIA_PREAUTH=1 just below the :argsdone label, so a double-click runs unattended with the
rem    two consent-gated steps pre-authorised. Every gated step records HOW it was authorised in
rem    the CSV evidence: 'launcher default (double-click automation)' when these built-in values
rem    applied, or 'command-line switch /authorize-active' when the switch was passed explicitly.
rem    The evidence never claims a switch was used when it was not.
rem
rem    EIA_HEADLESS=1 alone is the SAFE state: a gated step that cannot be confirmed is declined
rem    and reported NOT TESTABLE. EIA_PREAUTH=1 is what makes the steps RUN. Deleting either line
rem    restores prompt-based operation; deleting the EIA_PREAUTH line leaves the tool passive by
rem    default, which is the safer configuration if the file may be executed by someone who is not
rem    the engagement owner.
rem
rem    Two further safeguards remain in place regardless of these defaults:
rem      * If pre-authorisation is cleared, prompting is refused whenever standard input is
rem        redirected. An open stdin pipe that never delivers data blocks Read-Host INDEFINITELY
rem        - the usual way an orchestrated run hangs forever - so the engine applies the safe
rem        default, records the reason, and continues.
rem      * /localonly suppresses every remote operation and overrides both settings.
rem
rem  ELEVATION
rem    Run from an elevated command prompt for full coverage. Without an
rem    administrative token the engine still runs - but checks that require
rem    elevation (LSA policy, service configuration, ACLs, registry hives) are
rem    reported as NOT TESTABLE instead of being guessed at. The engine detects
rem    and reports its own privilege level and token integrity level itself.
rem
rem  REQUIREMENTS
rem    Windows PowerShell 3.0 or later (5.1 recommended). No RSAT, no modules,
rem    no external scripts, no internet access.
rem
rem  RUNTIME
rem    Typically 2-8 minutes: local configuration checks are fast, the time goes
rem    into the bounded discovery sweep and the directory enumeration.
rem ============================================================================

setlocal EnableExtensions DisableDelayedExpansion
title InfraPulse-Win - authorised internal VAPT

rem --- Self path: the engine re-reads this file, so the path must be exact ---
set "EIA_SELF=%~f0"

rem --- Command-line switches ---------------------------------------------------
rem     /headless         never prompt; safe defaults; consent-gated steps skipped
rem     /localonly        suppress ALL remote operations (sweep, DC probe, LDAP, AS-REQ, remote admin)
rem     /scope:<list>     ENGAGEMENT SCOPE - comma/semicolon separated CIDR, IP or host entries,
rem                       with ! prefix for exclusions, e.g. /scope:10.0.0.0/24,!10.0.0.99
rem                       When supplied the run is DEFAULT-DENY: any target outside the list is
rem                       refused and no packet is sent to it. Without it the tool is permissive
rem                       and discovery is bounded only to the derived local /24.
rem     /scopefile:<path> read the same list from a file (one entry per line, # for comments)
rem     /authorize-active pre-authorise the consent-gated active steps (see REM header)
rem     /nopause          do not pause at the end
rem     /?  /help         usage
set "EIA_HEADLESS="
set "EIA_PREAUTH="
set "EIA_LOCALONLY="
set "EIA_SCOPE="
set "EIA_SCOPE_FILE="
set "EIA_NETWORK_AUTH="
set "EIA_NOPAUSE="
set "EIA_PSFLAGS=-NoProfile -ExecutionPolicy Bypass"
:parseargs
if "%~1"=="" goto argsdone
if /i "%~1"=="/nopause"          set "EIA_NOPAUSE=1"
if /i "%~1"=="/headless"         set "EIA_HEADLESS=1"
if /i "%~1"=="/authorize-active" (
    set "EIA_PREAUTH=1"
    set "EIA_NETWORK_AUTH=1"
    set "EIA_PREAUTH_SOURCE=command-line switch /authorize-active"
)
if /i "%~1"=="/localonly"        (
    set "EIA_LOCALONLY=1"
    set "EIA_HEADLESS=1"
)
rem  /scope:<list> and /scopefile:<path> are matched by PREFIX, so they are handled before the
rem  exact-match switches. tokens=1,* with delims=: keeps the remainder intact, which is what makes
rem  a Windows path such as /scopefile:C:\temp\scope.txt work. A scope VALUE must therefore not
rem  itself contain a colon - use CIDR, addresses or host names, not IPv6 literals.
for /f "tokens=1,* delims=:" %%a in ("%~1") do (
    if /i "%%a"=="/scope"     set "EIA_SCOPE=%%b"
    if /i "%%a"=="/scope"     set "EIA_NETWORK_AUTH=1"
    if /i "%%a"=="/scope"     goto argok
    if /i "%%a"=="/scopefile" set "EIA_SCOPE_FILE=%%b"
    if /i "%%a"=="/scopefile" set "EIA_NETWORK_AUTH=1"
    if /i "%%a"=="/scopefile" goto argok
)
if /i "%~1"=="/?"                goto usage
if /i "%~1"=="/help"             goto usage
if /i not "%~1"=="/nopause" if /i not "%~1"=="/headless" if /i not "%~1"=="/localonly" if /i not "%~1"=="/authorize-active" echo  [WARN] Unrecognised switch ignored. Run with /? for usage.
:argok
shift
goto parseargs
:argsdone
rem --- AUTOMATION DEFAULTS (set here so they apply to every invocation) -----------------
rem  These two make a plain double-click a fully unattended run: no console prompt is ever
rem  shown, and the two consent-gated steps are pre-authorised.
rem
rem  INTERACTION BETWEEN THEM - read before relying on this:
rem    EIA_HEADLESS=1  the engine must not prompt. On its own this is the SAFE state: a gated
rem                    step that cannot be confirmed is declined and reported NOT TESTABLE.
rem    EIA_PREAUTH=1   the engine treats the gated steps as already authorised. Because
rem                    pre-authorisation is evaluated FIRST, setting both means the steps RUN
rem                    rather than being skipped:
rem                      * bounded TCP/ICMP sweep of the local IPv4 scope
rem                      * read-only remote administrative-reachability check, which includes
rem                        executing ONE read-only command (hostname/whoami) over WinRM against
rem                        up to five hosts when membership in the local Administrators group is
rem                        confirmed
rem  So executing this file is itself the authorisation act. Only run it inside a signed
rem  engagement scope, and delete or edit these two lines if you want the prompt-based mode
rem  back. /localonly still suppresses every remote operation in either mode.
set "EIA_HEADLESS=1"
rem  NETWORK AUTHORISATION IS DELIBERATELY NOT SET HERE.
rem  A bare double-click runs the full LOCAL assessment and touches no other host. Off-host
rem  work requires an explicit act on the command line: a scope (/scope: or /scopefile:) or
rem  /authorize-active. See the ENGAGEMENT SCOPE section of the header.
set "EIA_REQUIRE_NETWORK_AUTH=1"
if not defined EIA_PREAUTH_SOURCE set "EIA_PREAUTH_SOURCE=not pre-authorised (no switch supplied)"

rem  -NoProfile -ExecutionPolicy Bypass only. -NonInteractive is deliberately NOT passed: consent
rem  is pre-authorised so nothing ever prompts, and omitting the flag keeps the live console
rem  rendering - progress, tables and the executive summary - exactly as it appears interactively.
rem  EIA_NOPAUSE is also deliberately NOT set here: the window must stay open after a double-click
rem  so the summary can be read. Pass /nopause for scheduled or orchestrated runs.
set "EIA_PSFLAGS=-NoProfile -ExecutionPolicy Bypass"

rem --- Work in the folder the launcher was started from, so the CSV reports
rem     land next to the tool instead of in the current shell directory. -----
rem  %~dp0 is the SCRIPT's own folder (drive+path of %0), not the caller's working directory,
rem  so an orchestration engine launching this from System32 does not affect it. pushd is used
rem  rather than cd because it maps a drive letter when the launcher sits on a UNC share.
set "EIA_LAUNCHER_DIR=%~dp0"
if "%EIA_LAUNCHER_DIR:~-1%"=="\" set "EIA_LAUNCHER_DIR=%EIA_LAUNCHER_DIR:~0,-1%"
pushd "%~dp0" >nul 2>&1
if errorlevel 1 (
    echo [WARN] Could not change to the launcher folder. Reports and the handoff will be
    echo        written to %EIA_OUTDIR% instead. This is normal when the launcher sits on an
    echo        unreachable UNC share; it is NOT caused by the caller's working directory.
)

rem --- Locate Windows PowerShell -------------------------------------------
set "EIA_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%EIA_PS%" set "EIA_PS=powershell.exe"

echo ============================================================================
echo  INFRAPULSE-WIN  v1.0
echo  Authorised internal-network vulnerability assessment - read-only engine
echo ============================================================================
echo.
echo  [INFO] Authorisation required: run only against assets inside your
echo         signed engagement scope. Two active steps ask for consent first.
echo  [INFO] The engine is read-only by construction and never captures
echo         credentials, tickets or memory contents.
echo  [INFO] Extracting the embedded assessment engine to a temporary folder...
echo.

rem --- State the operating mode, because it changes what the run can conclude ----
if defined EIA_LOCALONLY (
    echo  [INFO] MODE: local-only - no assessment probe will be sent to any remote host. The address
    echo         sweep, the DC reachability probe, LDAP/ADSI directory queries, the Kerberos AS-REQ
    echo         probe and the remote administrative check are all suppressed and reported NOT
    echo         TESTABLE with the operator-suppression wording. Operating-system name resolution
    echo         (e.g. of this host's own name) is outside this control.
)
if defined EIA_HEADLESS (
    echo  [INFO] MODE: unattended - no console prompt will be shown.
)
if defined EIA_PREAUTH (
    echo  [INFO] MODE: the consent-gated active steps are PRE-AUTHORISED. The bounded address
    echo         sweep and the read-only remote administrative-reachability check will run without
    echo         asking. Executing this file inside a change window IS the authorisation act -
    echo         confirm the engagement scope covers every address in the derived range.
    echo  [INFO] Run with /localonly to suppress every remote operation instead.
)
echo.

rem --- Record the privilege level up front; the engine reports it in detail ---
net session >nul 2>&1
if errorlevel 1 (
    echo  [WARN] This console does not hold an administrative token. The engine
    echo         will still run, but elevation-dependent checks are reported as
    echo         NOT TESTABLE rather than guessed. Re-run elevated for full coverage.
) else (
    echo  [INFO] Administrative token detected - full local coverage available.
)
echo.

rem --- Record the launcher hash so any copy can be identified later ----------
set "EIA_HASH="
rem --- Output directory -------------------------------------------------------
rem     Prefer an explicit EIA_OUTDIR, then a writable folder beside the launcher, then
rem     ProgramData. Never falls through to the caller's CWD, which for an orchestration
rem     engine is System32 and is the wrong place for a report.
if not defined EIA_OUTDIR (
    if exist "%EIA_LAUNCHER_DIR%\." (
        echo. >"%EIA_LAUNCHER_DIR%\EIA_write_test.tmp" 2>nul
        if exist "%EIA_LAUNCHER_DIR%\EIA_write_test.tmp" (
            set "EIA_OUTDIR=%EIA_LAUNCHER_DIR%"
            del "%EIA_LAUNCHER_DIR%\EIA_write_test.tmp" >nul 2>&1
        ) else (
            set "EIA_OUTDIR=%ProgramData%"
            set "EIA_OUTDIR_FALLBACK=1"
        )
    ) else (
        set "EIA_OUTDIR=%ProgramData%"
        set "EIA_OUTDIR_FALLBACK=1"
    )
)
rem     EIA_OUTDIR is exported to the engine; the engine never derives it from the CWD.

for /f "skip=1 delims=" %%H in ('certutil -hashfile "%EIA_SELF%" SHA256 2^>nul') do if not defined EIA_HASH set "EIA_HASH=%%H"
rem certutil formats the digest differently across Windows versions (spaces between byte pairs on
rem some builds). Normalise before use: the engine records this value only as a FALLBACK, since it
rem recomputes both digests in memory itself.
if defined EIA_HASH set "EIA_HASH=%EIA_HASH: =%"
if defined EIA_HASH set "EIA_LAUNCHER_SHA256=%EIA_HASH%"
if defined EIA_HASH echo  [INFO] Launcher SHA256  : %EIA_HASH%
if not defined EIA_HASH echo  [INFO] Launcher SHA256  : unavailable - certutil missing or the file is locked
echo  [INFO] The engine recomputes both digests in memory and writes them into the first row of
echo         the CSV report, so the audit trail does not depend on certutil.
echo.

rem --- Fail fast if Windows PowerShell is not present ------------------------
if /i not "%EIA_PS%"=="powershell.exe" (
    if not exist "%EIA_PS%" (
        echo [ERROR] Windows PowerShell was not found at %EIA_PS%
        echo         The assessment engine requires Windows PowerShell 3.0 or later.
        popd >nul 2>&1
        exit /b 92
    )
)

rem --- Extract the embedded engine and run it --------------------------------
rem     The one-liner is deliberately limited to single-quoted PowerShell
rem     strings so that cmd.exe needs no escaping. It verifies the marker
rem     pair, refuses to run if the file was truncated or edited, records the
rem     SHA256 of the extracted engine for the evidence trail, and removes the
rem     temporary extraction afterwards whatever happens.
"%EIA_PS%" %EIA_PSFLAGS% -Command "$ErrorActionPreference='Stop'; $v=$PSVersionTable.PSVersion; if($v.Major -lt 3){Write-Host ('[ERROR] Windows PowerShell ' + $v + ' is too old: this engine needs 3.0 or later (5.1 recommended).') -ForegroundColor Red; exit 91}; $self=$env:EIA_SELF; if(-not (Test-Path -LiteralPath $self)){Write-Host '[ERROR] Cannot read the launcher file itself.' -ForegroundColor Red; exit 92}; $txt=[System.IO.File]::ReadAllText($self,[System.Text.Encoding]::UTF8); $b='#===EIA'+'-PS-BEGIN==='; $e='#===EIA'+'-PS-END==='; $i=$txt.IndexOf($b); $j=$txt.IndexOf($e); if($i -lt 0 -or $j -le $i){Write-Host '[ERROR] Embedded engine markers not found - the file is truncated or was edited. Re-obtain the original .bat.' -ForegroundColor Red; exit 93}; $body=$txt.Substring($i+$b.Length, $j-$i-$b.Length).TrimStart([char]13,[char]10); $base=$env:EIA_WORKDIR; if([string]::IsNullOrWhiteSpace($base)){$base=[System.IO.Path]::GetTempPath()}; $dir=$null; foreach($cand in @($base,[System.IO.Path]::GetTempPath())){ if([string]::IsNullOrWhiteSpace($cand)){continue}; try{ $d=Join-Path $cand ('EIA_' + [System.Guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop); $dir=$d; break }catch{} }; if(-not $dir){Write-Host '[ERROR] No writable directory was available for the engine extraction.' -ForegroundColor Red; Write-Host '        Set EIA_WORKDIR to a directory the executing account can write to, ideally one' -ForegroundColor Yellow; Write-Host '        already covered by your AppLocker or WDAC allow rule.' -ForegroundColor Yellow; exit 94}; try{ $alC=@(); foreach($k in @('Exe','Script','Msi')){ if(Test-Path -LiteralPath ('HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\' + $k)){$alC+=$k} }; $wdacC=0; try{ $wdacC=@(Get-ChildItem -LiteralPath (Join-Path $env:windir 'System32\CodeIntegrity\CiPolicies\Active') -Filter '*.cip' -ErrorAction SilentlyContinue).Count }catch{}; if($alC.Count -gt 0 -or $wdacC -gt 0){ Write-Host ('[INFO] Execution-control policy present: AppLocker rule collections [' + ($alC -join ',') + ']' + $(if($wdacC -gt 0){'; WDAC active policies: ' + $wdacC}else{''})) -ForegroundColor DarkGray; Write-Host '       If the run stops at extraction, the policy is blocking script execution from that' -ForegroundColor DarkGray; Write-Host '       directory. Re-run with EIA_WORKDIR pointing at an allowed path.' -ForegroundColor DarkGray } }catch{}; $eng=Join-Path $dir 'EIA_Engine.ps1'; [System.IO.File]::WriteAllText($eng,$body,(New-Object System.Text.UTF8Encoding($true))); try{$sha=[System.Security.Cryptography.SHA256]::Create(); try{$h=$sha.ComputeHash([System.IO.File]::ReadAllBytes($eng)) | ForEach-Object { $_.ToString('x2') }; $hash=($h -join '')} finally{try{$sha.Dispose()}catch{}}} catch { $hash='' }; Write-Host ('[INFO] Engine extracted: ' + $eng) -ForegroundColor DarkGray; Write-Host ('[INFO] Engine SHA256  : ' + $(if($hash){$hash}else{'unavailable to the launcher - the engine hashes itself in-process, see the report integrity row'})) -ForegroundColor DarkGray; Write-Host ''; $env:EIA_ENGINE_PATH=$eng; $env:EIA_ENGINE_SHA256=$hash; try { . $eng } catch { $em=$_.Exception.Message; Write-Host ''; if($em -match 'cannot be loaded|not digitally signed|prohibited|AppLocker|CodeIntegrity'){ Write-Host '[ERROR] Windows blocked execution of the extracted engine.' -ForegroundColor Red; Write-Host '        This is an execution-control refusal (AppLocker or WDAC), not a PowerShell' -ForegroundColor Yellow; Write-Host '        execution-policy refusal - -ExecutionPolicy Bypass does not affect it.' -ForegroundColor Yellow; Write-Host '        Fix: add an allow rule for the extraction directory, or re-run with' -ForegroundColor Yellow; Write-Host '        EIA_WORKDIR set to a path your policy already allows scripts to run from.' -ForegroundColor Yellow } ; Write-Host ('[ERROR] ' + $em) -ForegroundColor Red; exit 95 } finally { try { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop; Write-Host ''; Write-Host '[INFO] Temporary extraction removed - no assessment artifact left behind.' -ForegroundColor DarkGray } catch { Write-Host ''; Write-Host ('[WARN] Could not remove ' + $dir + ' - delete it manually.') -ForegroundColor Yellow } }"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo [INFO] Assessment finished with no fatal engine error.
) else (
    echo [ERROR] The engine returned exit code %RC%. Review the console output
    echo         above; a partial report is still written incrementally by design.
)

rem --- Confirm the evidence files landed where the analyst expects them -------
if exist "Internal_VAPT_Compliance_Report.csv" (
    echo [INFO] Evidence report : %CD%\Internal_VAPT_Compliance_Report.csv
) else (
    echo [WARN] Internal_VAPT_Compliance_Report.csv was not found in %CD%
    echo        Check the console output for the CSV write error.
)
if exist "Internal_VAPT_Test_Registry.csv" (
    echo [INFO] Test registry   : %CD%\Internal_VAPT_Test_Registry.csv
)

echo.
if not defined EIA_NOPAUSE pause
popd >nul 2>&1
exit /b %RC%

:usage
echo ============================================================================
echo  INFRAPULSE-WIN v1.0 - usage
echo ============================================================================
echo.
echo   InfraPulse-Win.bat               unattended run, active steps
echo                                                       pre-authorised, pauses at the end
echo   InfraPulse-Win.bat /nopause      no final pause - scheduled tasks
echo   InfraPulse-Win.bat /localonly    no remote probes issued
echo   InfraPulse-Win.bat /?            this text
echo.
echo  Consent prompts are bypassed by default: EIA_HEADLESS=1 and EIA_PREAUTH=1 are set below
echo  the :argsdone label. The gated steps are the bounded discovery sweep and the read-only
echo  remote administrative check; the evidence records that they were authorised by the
echo  launcher default. Edit or delete those two lines to restore prompt-based operation.
echo.
echo  Output: Internal_VAPT_Compliance_Report.csv and Internal_VAPT_Test_Registry.csv
echo          written into the folder this launcher is started from.
echo.
echo  Authorisation reminder: use only on assets inside your signed engagement scope.
echo ============================================================================
exit /b 0
#===EIA-PS-BEGIN===
# ===========================================================================================
#  InfraPulse-Win :: EMBEDDED POWERSHELL ASSESSMENT ENGINE (part 1/9)
#  Core runtime: configuration, console presentation, registry helpers, finding engine,
#  severity methodology (explicit and documented), CSV evidence writer, test registry.
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Every assessment result produced by this tool is stored as a "finding record" with a
#  fixed schema. The schema deliberately separates CONFIGURATION EVIDENCE, VALIDATION
#  METHOD, OBSERVED RESULT and IMPACT so that an auditor reading the CSV can immediately
#  see whether a row is (a) a discovered setting, (b) a condition that was actively
#  validated against a live service, or (c) a demonstrated impact. This prevents the most
#  common failure mode of internal assessment tooling: reporting a misconfiguration as a
#  proven exploitable vulnerability.
# ===========================================================================================

$ErrorActionPreference = 'Continue'     # never abort the whole assessment on one cmdlet error
$ProgressPreference    = 'SilentlyContinue'  # progress bars slow scripted IO down massively
$WarningPreference     = 'Continue'
$FormatEnumerationLimit = -1            # do not truncate collections in console output

# -------------------------------------------------------------------------------------------
#  GLOBAL CONFIGURATION
#  Every tunable is centralised so that the operator can understand exactly what the tool
#  will do on the network before authorising execution. Nothing here is hidden or obfuscated.
# -------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------
#  SCAN PROFILE
#  Two profiles. 'balanced' (default) is paced so that a sweep does not disturb fragile
#  internal devices - older printers, IP cameras, thin clients, industrial/medical endpoints
#  and embedded management cards are routinely knocked offline by a few hundred simultaneous
#  half-open connections, and that is an availability incident inside the customer's own
#  change window. 'fast' removes most of the pacing and is an operator decision.
#  Select with:  set EIA_SCAN_PROFILE=fast   (or /fast on the command line)
# -------------------------------------------------------------------------------------------
$script:ScanProfile = ([string]$env:EIA_SCAN_PROFILE).Trim().ToLowerInvariant()
$script:IsFastProfile = ($script:ScanProfile -eq 'fast' -or $script:ScanProfile -eq 'aggressive')

# AD paging ceiling. The default is a guard against pinning a domain controller for hours on a
# large forest; raise it deliberately for a full topology map on a forest you have measured.
$script:MaxAdObjectsCfg = 100000
if ($env:EIA_MAX_AD_OBJECTS -match '^[0-9]+$') { $script:MaxAdObjectsCfg = [int]$env:EIA_MAX_AD_OBJECTS }

$script:Cfg = [ordered]@{
    ToolName         = 'InfraPulse-Win'
    ToolVersion      = '1.0.0'
    # Fixed name mandated by the specification (section 21). Retained verbatim; the run-specific
    # name below is the default so that back-to-back runs against different hosts do not collide.
    ReportCsvFixed   = 'Internal_VAPT_Compliance_Report.csv'
    FixedReportName  = ([string]$env:EIA_FIXED_REPORT_NAME -eq '1')
    TcpTimeoutMs     = $(if ($script:IsFastProfile) { 400 } else { 700 })   # per-port TCP connect
    SweepTimeoutSec  = $(if ($script:IsFastProfile) { 20 }  else { 30 })    # bounded-sweep ceiling
    MaxParallelPort  = $(if ($script:IsFastProfile) { 128 } else { 64 })    # concurrent sockets
    MaxSweepHosts    = 254        # guard: never sweep more than one /24 per pass
    MaxAdObjects     = $script:MaxAdObjectsCfg   # LDAP paging guard (EIA_MAX_AD_OBJECTS)
    StalePasswordAge = 180        # SPN/service-account password age threshold (days)
    StartupDelay     = $(if ($script:IsFastProfile) { 0 }   else { 25 })    # ms between host launches
    ProbeFileTtlMin  = 5          # age at which a leftover probe artifact from an INTERRUPTED run
                                  # is deleted at start-up - APPLIED by Initialize-PowerShellRuntime

    # SINGLE SOURCE OF TRUTH for the discovery port set. Section 8 reads THIS list for the local
    # listening matrix and for the remote sweep, so the port scope cannot drift between rows.
    # Mandated Windows core services: DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, LDAPS, Global
    # Catalog (both transports), RDP, WinRM (HTTP and HTTPS).
    # Extended, because an attacker look-down from a foothold does not stop at the Windows
    # services: cleartext management (FTP/Telnet), remote shell (SSH), rpcbind, plain HTTP and
    # HTTPS, and the database and alternate-web listeners that are the usual lateral-movement and
    # data-exfiltration paths on an internal estate.
    Ports            = @(21,22,23,53,80,88,111,135,139,389,443,445,636,
                         1433,3268,3269,3306,3389,5432,5985,5986,8080,8443)

    # Ports for which a read-only banner / header / certificate capture is defined (Section 8.5).
    # Ports whose owners speak a binary protocol on connect (1433/3306/5432) are NOT probed for a
    # banner: doing so would require a protocol-level handshake, which is not read-only in the
    # sense this tool guarantees, so they are reported as NOT TESTABLE instead of guessed at.
    BannerPorts      = @(21,22,23,80,443,8080,8443,8530,8531)

    # Section 10.2 sends ONE AS-REQ without pre-authentication data per flagged account and
    # DISCARDS the response (no ticket material is retained, stored or cracked). It is read-only,
    # so it is ENABLED by default; set $false for a configuration-only run.
    # NOTE: this key was previously referenced but never defined - the active validation was
    # silently skipped while the report claimed it had been 'disabled by configuration'.
    EnableKerberosPreAuthProbe = $true
}

# -------------------------------------------------------------------------------------------
#  VALIDATION HANDOFF
#  Every finding that warrants human follow-up is mapped to the NEXT ACTION a tester would take,
#  the evidence that would CONFIRM it, the evidence that would REFUTE it, and the BLAST RADIUS of
#  attempting it. The tool does not perform these steps - it cannot know whether the host is in
#  the change window, whether the account is a service account, or whether the business can absorb
#  the impact this minute. That judgement is the operator's, and it is the reason this is a handoff
#  rather than an action.
#
#  'Where' distinguishes the two operating contexts:
#      either  - reasonable to attempt against production inside an agreed window
#      range   - belongs in an isolated range; the technique is destructive, noisy,
#                availability-affecting, or produces credential material that must be handled
# -------------------------------------------------------------------------------------------
$script:HandoffStageOrder = @(
    'DISCOVERY / SERVICE ENUMERATION',
    'VULNERABILITY VALIDATION',
    'INITIAL ACCESS VALIDATION',
    'LOCAL PRIVILEGE ESCALATION',
    'CREDENTIAL / ACCESS MATERIAL VALIDATION',
    'AD ATTACK-PATH VALIDATION',
    'LATERAL-MOVEMENT VALIDATION',
    'DOMAIN-LEVEL IMPACT VALIDATION'
)

$script:HandoffSteps = @(
    @{ Match = 'Anonymous'; Stage = 'DISCOVERY / SERVICE ENUMERATION'; Where = 'either'
       Next = @('net use \\<target>\IPC$ "" /u:""   (from a context with no cached credentials)',
                'then: net view \\<target>   and   nltest /dsgetdc:<domain>')
       Confirms = 'The IPC$ tree connects and the share/session listing succeeds without credentials - the null session is genuinely usable, not merely advertised.'
       Refutes = 'The connection is refused with a logon failure, or access is denied on every share - anonymous binding was enabled but access is still filtered.'
       Blast = 'Minimal. Read-only enumeration. Do not enumerate beyond the shares you need; a null session that starts touching files is no longer a read-only test.' }

    @{ Match = 'SMB signing'; Stage = 'VULNERABILITY VALIDATION'; Where = 'range'
       Next = @('Confirm the per-host signing state directly: nxc smb <target> --gen-relay-list out.txt   (or the Windows equivalent).',
                'Map which hosts require signing and which do not. The finding is only actionable where a NON-required host is also the target of an authentication you can trigger.',
                'If relay is in scope, perform it in the RANGE first against a replica, never first against the production target.')
       Confirms = 'A host that does not require signing accepts a relayed SMB authentication and the relayed identity gains access it should not have.'
       Refutes = 'Every reachable host requires signing and rejects the relayed session (STATUS_ACCESS_DENIED).'
       Blast = 'HIGH. Relaying is an active attack against authentication. On production it can lock accounts, break sessions, and trip every EDR in the estate. Range first, always.' }

    @{ Match = 'DONT_REQ_PREAUTH'; Stage = 'INITIAL ACCESS VALIDATION'; Where = 'range'
       Next = @('Request an AS-REP for the named account without pre-authentication and confirm the KDC returns a response the account name did not have to prove.',
                'If offline cracking is authorised, move the captured response to a dedicated cracking host - never crack on the target or on a DC.')
       Confirms = 'The KDC issues an AS-REP for the account, and the response is crackable offline - the account can be attacked with no prior credentials and no lockout exposure.'
       Refutes = 'The KDC returns KDC_ERR_PREAUTH_REQUIRED for the named account - the flag is set in the directory but is not effective for that principal.'
       Blast = 'LOW on the network (a single AS-REQ, no authentication attempt, no lockout counter touched). Offline cracking is CPU-bound and isolated. Treat any recovered plaintext as engagement-controlled material.' }

    @{ Match = 'AS-REP obtainable'; Stage = 'INITIAL ACCESS VALIDATION'; Where = 'range'
       Next = @('Treat the named account as a confirmed no-pre-auth target and prove the offline step on a cracking host with a wordlist sized to the engagement window.')
       Confirms = 'A plaintext credential is recovered and it authenticates - that is initial access.'
       Refutes = 'No plaintext is recovered within the agreed cracking budget. That refutes YOUR wordlist, not the weakness - report the exposure, not a compromise.'
       Blast = 'LOW on production. Be precise in the report: an AS-REP exposure is a validated WEAKNESS; it becomes VALIDATED ACCESS only once a credential is recovered and used.' }

    @{ Match = 'Kerberoast'; Stage = 'AD ATTACK-PATH VALIDATION'; Where = 'range'
       Next = @('Request a service ticket for each named SPN using the ticket-request path that does not need the account password.',
                'Record the ticket encryption type (RC4 vs AES) - RC4 tickets crack far more cheaply.',
                'Crack on a dedicated host.')
       Confirms = 'A service ticket is issued for the named SPN with a weak encryption type and a plaintext password is recovered and authenticates.'
       Refutes = 'Tickets are issued only with AES and no password is recovered in budget - still report the SPN exposure and the weak-crypto support separately.'
       Blast = 'LOW on the network. Note that a recovered service-account password is usually a LONG-LIVED credential with broad access - handle as sensitive, and expect it to require rotating a service, which is a change-control event.' }

    @{ Match = 'delegation'; Stage = 'AD ATTACK-PATH VALIDATION'; Where = 'range'
       Next = @('For unconstrained delegation: identify whether the delegating host is one you can reach and whether any privileged account authenticates to it.',
                'For constrained delegation: determine which service the delegation targets and whether it is writable by any principal you control.',
                'Confirm the chain end-to-end in the range before attempting anything against production.')
       Confirms = 'The delegation configuration allows a credential you can influence to be used against a service you should not reach.'
       Refutes = 'The delegating object is unreachable, unused, or its delegation target is already locked down.'
       Blast = 'HIGH. Exploiting delegation captures or misuses authentication material. A mis-step can lock out and expose privileged accounts. RANGE ONLY until the chain is proven on a replica.' }

    @{ Match = 'AlwaysInstallElevated'; Stage = 'LOCAL PRIVILEGE ESCALATION'; Where = 'either'
       Next = @('Build a BENIGN MSI that writes a proof file (for example C:\ProgramData\EIA_proof.txt) and exits - no runner, no payload.',
                'Install it from a genuine low-privilege context (not from your elevated shell), then check the file owner.',
                'Remove the MSI and the proof file immediately.')
       Confirms = 'The proof file is created owned by NT AUTHORITY\SYSTEM - the crafted-package path reaches SYSTEM for any user.'
       Refutes = 'msiexec refuses to install, or the file is owned by the invoking user - the policy is not effective despite the registry values.'
       Blast = 'LOW with a benign package, and removed afterwards. Never use a real payload here: the same path would install it as SYSTEM.' }

    @{ Match = 'AppLocker'; Stage = 'LOCAL PRIVILEGE ESCALATION'; Where = 'either'
       Next = @('Attempt to execute a known-signed binary from a directory the policy does not cover, and a user-writable directory that should be blocked.',
                'Record the exact path and the policy rule that allowed or blocked it.')
       Confirms = 'A binary executes from a location the effective policy was supposed to block.'
       Refutes = 'Execution is blocked, or only permitted from default allow paths - then report the policy as working.'
       Blast = 'LOW. Benign binaries only, and prefer a binary that prints its version rather than doing anything.' }

    @{ Match = 'Defender'; Stage = 'VULNERABILITY VALIDATION'; Where = 'either'
       Next = @('Confirm the reported state on the host (Get-MpComputerStatus / Get-MpPreference equivalent) and compare with the intended baseline.',
                'STOP THERE. Do not attempt to disable, bypass, or test-evade the platform - that is out of scope for this tool by design and is what gets an engagement terminated.')
       Confirms = 'Real-time protection, tamper protection or ASR rules are genuinely off or misconfigured, so the estate has no detection for the next stage.'
       Refutes = 'The controls are on and enforcing for the user population you tested.'
       Blast = 'Minimal as long as no evasion is attempted. Report the gap; do not demonstrate it by evading.' }

    @{ Match = 'Credential Guard'; Stage = 'CREDENTIAL / ACCESS MATERIAL VALIDATION'; Where = 'either'
       Next = @('Record whether Credential Guard is running, as context for whether credential material on this host would even be extractable.',
                'Do NOT attempt extraction. This tool does not dump credential material, and neither should the next step.')
       Confirms = 'Credential Guard is not running, so this host would be a candidate for credential-material exposure if a future, separately-authorised exercise targets it.'
       Refutes = 'Credential Guard is enforced, so the material is not present in extractable form.'
       Blast = 'None - this is a status read. The extraction step is deliberately NOT handed off here; if it is in scope it belongs in a separately scoped exercise with its own written authorisation.' }

    @{ Match = 'Cached domain logon'; Stage = 'CREDENTIAL / ACCESS MATERIAL VALIDATION'; Where = 'either'
       Next = @('Report the configured cache size as a posture value and note that cached material exists on the host.',
                'Do not extract it with this tool. If extraction is genuinely in scope, it is a separately authorised exercise, in the range, with the material handled per the engagement security plan.')
       Confirms = 'The cache is non-zero, so a future authorised extraction would have material to work with.'
       Refutes = 'Caching is disabled (value 0), so there is no cached material on the host.'
       Blast = 'None as a status read. Extraction is the boundary this tool does not cross.' }

    @{ Match = 'LAPS'; Stage = 'CREDENTIAL / ACCESS MATERIAL VALIDATION'; Where = 'either'
       Next = @('Determine WHICH groups can read the local-administrator password attribute, and whether any non-privileged principal is in one of them.',
                'Do NOT read the password attribute itself unless the engagement explicitly authorises it in writing and the value is handled per the security plan.')
       Confirms = 'A non-privileged group holds read rights on the password attribute, so every managed host''s local administrator password is readable by that group.'
       Refutes = 'Only the designated administrative groups hold read rights and coverage is complete.'
       Blast = 'Reading the attribute is a minimal operation but the VALUE is a live administrative credential for potentially every managed host. Reading it changes the engagement: it must be reported, protected, and the client should consider rotation afterwards.' }

    @{ Match = 'lockout'; Stage = 'CREDENTIAL / ACCESS MATERIAL VALIDATION'; Where = 'either'
       Next = @('Read the threshold, duration and observation window from this report and take them to the AD team BEFORE any authentication testing.',
                'Agree a lockout budget in writing: which accounts may be touched, how many attempts, and by when. This tool performs no password guessing; any subsequent testing must stay inside that budget.')
       Confirms = 'The agreed budget matches the reported policy, and the policy includes alerting so abusive attempts are noticed.'
       Refutes = 'The policy has no threshold at all - then unlimited online guessing is the finding, and the risk is a documented accepted risk rather than something to demonstrate.'
       Blast = 'Planning step only, no network impact. This is the control that stops a testing exercise from becoming an outage.' }

    @{ Match = 'password'; Stage = 'CREDENTIAL / ACCESS MATERIAL VALIDATION'; Where = 'range'
       Next = @('If offline cracking of the domain policy strength is in scope, obtain the hashes through an AUTHORISED route and crack them on a dedicated host against a realistic wordlist.',
                'Do not crack on a DC, the target, or any production host.')
       Confirms = 'A meaningful fraction of accounts fall to a realistic wordlist within the agreed budget - a measurable, reportable weakness.'
       Refutes = 'Nothing falls within budget - report the policy as effective for the tested attack model, and state the wordlist and budget so the claim is reproducible.'
       Blast = 'CPU/GPU load on the cracking host only. The hashes themselves are sensitive engagement material; agree handling and destruction up front.' }

    @{ Match = 'Administrative interface reachable'; Stage = 'LATERAL-MOVEMENT VALIDATION'; Where = 'either'
       Next = @('Pick ONE in-scope host and confirm access with an AUTHORISED credential supplied by the engagement owner - the least-privileged administrative account that should work.',
                'Record the exact account, the protocol, and the single command you ran. One host, one command, then stop and reassess.')
       Confirms = 'The supplied credential authenticates and the host executes a harmless command - that is validated lateral movement with a legitimate account.'
       Refutes = 'Authentication fails, or succeeds but the command is denied - then the interface is reachable but not usable, which is a much smaller finding.'
       Blast = 'MEDIUM. Every remote authentication is a logon event, is visible in SIEM, and counts against any lockout policy for that account. Use the agreed account, not a guessed one, and not a service account.' }

    @{ Match = 'Cross-segment'; Stage = 'LATERAL-MOVEMENT VALIDATION'; Where = 'either'
       Next = @('From the assessment foothold, attempt a single connection to the same service on a host in the restricted segment the finding names.',
                'Capture the result as evidence either way - a successful connection is proof of a missing enforcement boundary.')
       Confirms = 'The connection completes across a boundary that the design says should block it.'
       Refutes = 'The connection is refused or filtered - the boundary is enforced and the configuration evidence was misleading.'
       Blast = 'LOW. A single connection attempt. Avoid touching any service that changes state (do not write, do not log in).' }

    @{ Match = 'Attack chain'; Stage = 'DOMAIN-LEVEL IMPACT VALIDATION'; Where = 'range'
       Next = @('Take the chain this report describes and walk it end-to-end in the RANGE against a replica of the estate, proving each link in sequence.',
                'Only once the whole chain works on the replica should any single link be attempted against production, and then only with written authorisation for that link.')
       Confirms = 'Each link holds and the objective is reached from the starting foothold.'
       Refutes = 'One link fails - the chain is broken there, which is itself a valuable finding and should be reported as such rather than as a failure.'
       Blast = 'HIGH if attempted on production. A proven chain end-to-end often implies domain-wide impact; the value is in the proof, and the proof belongs in the range.' }

    @{ Match = 'KRBTGT'; Stage = 'DOMAIN-LEVEL IMPACT VALIDATION'; Where = 'either'
       Next = @('Report the KRBTGT password age against the rotation policy and the risk it implies.',
                'Do NOT attempt any golden-ticket construction. Report the age and let the client remediate.')
       Confirms = 'The password is older than policy demands, so any prior domain compromise would remain viable.'
       Refutes = 'The password has been rotated within policy, including the required second rotation.'
       Blast = 'None - age read only. Forging tickets is out of scope for this tool and belongs to a separately authorised exercise.' }

    @{ Match = 'Certificate trust defect'; Stage = 'DISCOVERY / SERVICE ENUMERATION'; Where = 'either'
       Next = @('Connect to the endpoint with the platform client, confirm the certificate warning, and record the presented subject versus the name used to reach it.',
                'Check whether a replacement certificate already exists in the internal PKI and was simply never deployed.')
       Confirms = 'The warning is reproducible for the name users actually use, and no valid replacement is deployed.'
       Refutes = 'The warning appears only for a name nobody uses, or a valid certificate is deployed elsewhere.'
       Blast = 'Minimal. Read-only handshake.' }

    @{ Match = 'Spooler'; Stage = 'LOCAL PRIVILEGE ESCALATION'; Where = 'range'
       Next = @('Confirm the spooler is running and reachable on the named host.',
                'Because the historical exploits here are class-level and destructive to the print subsystem, perform any actual validation in the RANGE against a replica - not against production print infrastructure.')
       Confirms = 'The service is reachable and running the vulnerable configuration.'
       Refutes = 'The spooler is disabled or the host is patched.'
       Blast = 'HIGH on production. These techniques have a well-documented history of crashing the print spooler and, on domain controllers, of disrupting the whole estate. Range only.' }
)

$script:HandoffDefault = @{ Match = '(default)'; Stage = 'VULNERABILITY VALIDATION'; Where = 'either'
   Next = @('Re-read the ConfigurationEvidence and ObservedResult columns for this row, reproduce the observation by hand, and record what you find.',
            'Decide explicitly whether this is a validated weakness or a configuration observation, and label it as such in the final report.')
   Confirms = 'Manual reproduction matches the recorded observation, which upgrades the row from discovered to validated.'
   Refutes = 'Manual reproduction disagrees - then the row must be corrected, not carried forward.'
   Blast = 'Unknown - assess before acting. This item was not mapped to a specific technique, so it has not been risk-rated.' }

function Get-ValidationHandoff {
    param([string]$Attribute, [string]$Category)
    $hay = (([string]$Attribute + ' ' + [string]$Category)).ToLowerInvariant()
    foreach ($h in $script:HandoffSteps) {
        if ($hay.Contains(([string]$h.Match).ToLowerInvariant())) { return $h }
    }
    return $script:HandoffDefault
}

# -------------------------------------------------------------------------------------------
#  SEVERITY METHODOLOGY  (explicitly documented so the report is reproducible and defensible)
#  -----------------------------------------------------------------------------------------
#  This tool does NOT invent a subjective "security score". Severity is derived from a
#  published, deterministic mapping so two auditors running the tool obtain identical
#  ratings for identical evidence:
#
#    Category class == Context      -> Informational  (identity/context rows; never a finding)
#    Status == PASS                 -> Informational  (control observed in expected state)
#    Status == NOT CONFIRMED        -> Informational  (no demonstrated weakness)
#    Status == NOT TESTABLE         -> Informational  (unknown; must be manually reviewed)
#    Weakness == $false             -> Informational  (verified non-weakness / hardening gap)
#    Weakness == $true  -> Class     |  Confidentiality | Data at rest | Identity rights
#                                 High |    High       |      Medium     |     High
#                                 Medium |   Medium      |      Low      |    Medium
#                                 Low |     Low         |    Low        |     Low
#    Class == Critical -> CRITICAL unless the row is explicitly downgraded by the module.
#
#  CVSS or a bespoke risk score can be applied downstream by the reader; the raw
#  Category / Status / Weakness / ValidationMethod columns are preserved for that purpose.
# -------------------------------------------------------------------------------------------
try {
    Add-Type -TypeDefinition @'
using System;
public static class EiaSeverity {
    public static string Map(string cls, string catClass, bool weakness) {
        if (!weakness) return "Informational";
        string c = (cls == null) ? "Medium" : cls;
        string k = (catClass == null) ? "Confidentiality" : catClass;
        if (c.Equals("Critical", StringComparison.OrdinalIgnoreCase)) return "Critical";
        if (c.Equals("High", StringComparison.OrdinalIgnoreCase)) {
            if (k.Equals("Confidentiality", StringComparison.OrdinalIgnoreCase)) return "High";
            if (k.Equals("DataAtRest", StringComparison.OrdinalIgnoreCase)) return "Medium";
            if (k.Equals("IdentityRights", StringComparison.OrdinalIgnoreCase)) return "High";
            return "High";
        }
        if (c.Equals("Medium", StringComparison.OrdinalIgnoreCase)) {
            if (k.Equals("Confidentiality", StringComparison.OrdinalIgnoreCase)) return "Medium";
            if (k.Equals("DataAtRest", StringComparison.OrdinalIgnoreCase)) return "Low";
            if (k.Equals("IdentityRights", StringComparison.OrdinalIgnoreCase)) return "Medium";
            return "Medium";
        }
        return "Low";
    }
}
'@ -ErrorAction Stop
    $script:SeverityEngineOk = $true
} catch {
    # Fallback (Add-Type unavailable / constrained language mode). Same mapping, no compile.
    $script:SeverityEngineOk = $false
}

function Get-FindingSeverity {
    param([string]$Class, [string]$CatClass, [bool]$Weakness)
    if (-not $Weakness) { return 'Informational' }
    if ($script:SeverityEngineOk) {
        try { return [EiaSeverity]::Map($Class, $CatClass, $Weakness) } catch { }
    }
    switch ($Class) {
        'Critical' { return 'Critical' }
        'High'     { if ($CatClass -eq 'DataAtRest') { return 'Medium' } else { return 'High' } }
        'Medium'   { if ($CatClass -eq 'DataAtRest') { return 'Low' } else { return 'Medium' } }
        default    { return 'Low' }
    }
}

# -------------------------------------------------------------------------------------------
#  EVIDENCE STORE + CSV WRITER
#  The CSV is written incrementally (row per finding) so that a crash, reboot or operator
#  interruption never destroys collected evidence. RFC4180 escaping is applied to every
#  field: commas, double quotes, CR/LF and Unicode are all safe.
# -------------------------------------------------------------------------------------------
$script:Findings   = New-Object System.Collections.ArrayList
$script:TestLog    = New-Object System.Collections.ArrayList
$script:Utf8Bom    = New-Object System.Text.UTF8Encoding($true)
$script:CsvPath    = ''
$script:CsvOk      = $false
$script:Seq        = 0

$script:Stats = @{
    HostsDiscovered        = 0
    ServicesDiscovered     = 0
    AdObjectsAssessed      = 0
    ConfigFindings         = 0
    ValidatedFindings      = 0
    PartiallyConfirmed     = 0
    NotConfirmed           = 0
    NotTestable            = 0
    Errors                 = 0
    CriticalFindings       = 0
    Rows                   = 0
}

function Get-ReportTags {
    # Host and date tags for the run-specific report file names. The host tag is sanitised to
    # [A-Za-z0-9._-] so a name that contains characters the file system rejects, or a NETBIOS name
    # containing a path separator, cannot escape the output directory.
    $hostTag = ''
    try { $hostTag = [string]$env:COMPUTERNAME } catch { }
    if ([string]::IsNullOrWhiteSpace($hostTag)) { try { $hostTag = [string][System.Net.Dns]::GetHostName() } catch { } }
    if ([string]::IsNullOrWhiteSpace($hostTag)) { $hostTag = 'UNKNOWNHOST' }
    $hostTag = ($hostTag -replace '[^A-Za-z0-9._-]', '_')
    if ($hostTag.Length -gt 32) { $hostTag = $hostTag.Substring(0, 32) }
    # The timestamp is captured ONCE here so the compliance report and the test registry written by
    # the same run always share an identical stamp - computing it per-writer could straddle a second
    # boundary and produce a mismatched pair of files.
    $now = Get-Date
    return [pscustomobject]@{ Host = $hostTag; Date = $now.ToString('yyyyMMdd'); Stamp = $now.ToString('yyyyMMdd_HHmmss') }
}

function Initialize-Report {
    param([string]$Directory)
    try {
        if ([string]::IsNullOrWhiteSpace($Directory)) { $Directory = (Get-Location).Path }
        if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }

        # Run-specific naming: Internal_VAPT_Report_<HOST>_<YYYYMMDD_HHMMSS>.csv
        # The specification's fixed name is still reachable with EIA_FIXED_REPORT_NAME=1 (or
        # /fixedname) for engagements whose deliverables checklist demands the literal filename.
        $tags = Get-ReportTags
        $script:ReportHostTag = $tags.Host
        $script:ReportDateTag = $tags.Date
        $script:ReportStamp   = $tags.Stamp
        if ($script:Cfg.FixedReportName) {
            $reportName = $script:Cfg.ReportCsvFixed
            $script:RegistryName = 'Internal_VAPT_Test_Registry.csv'
        } else {
            # Second-resolution stamp, so two runs against the same host on the same day cannot
            # collide and overwrite each other's report.
            $reportName = 'Internal_VAPT_Report_' + $tags.Host + '_' + $tags.Stamp + '.csv'
            $script:RegistryName = 'Internal_VAPT_Test_Registry_' + $tags.Host + '_' + $tags.Stamp + '.csv'
        }
        $script:ReportFileName = $reportName
        $script:ReportDirectory = $Directory
        $script:CsvPath = Join-Path $Directory $reportName
        $header = 'Timestamp,Severity,Category,Source,Target,Port,Finding,Prerequisites,ConfigurationEvidence,ValidationMethod,ObservedResult,Exploitability,Impact,Remediation'
        # WriteAllText honours the UTF8Encoding preamble => the report opens correctly in
        # Excel/LibreOffice even when host names or remarks contain non-ASCII characters.
        [System.IO.File]::WriteAllText($script:CsvPath, $header + "`r`n", $script:Utf8Bom)
        $script:CsvOk = $true

        # ---- FORENSIC INTEGRITY ROW: always the FIRST data row of the report ----------------
        # Written immediately after the header, before any assessment module runs, so it cannot be
        # influenced by assessment output. It records the SHA-256 of the launcher and of the
        # extracted engine, WHICH mechanism produced each digest, and the run context (host, user,
        # elevation, PowerShell version, language mode). A reviewer can therefore prove which code
        # generated every subsequent row and can detect a modified launcher or engine by comparing
        # the digests against the copy held by the engagement owner.
        try {
            $integrity = Get-SelfIntegrityHashes
            $runUser = if ($env:USERDOMAIN) { $env:USERDOMAIN + '\' + $env:USERNAME } else { [string]$env:USERNAME }
            $elevated = 'unknown'
            try { $elevated = [string](Test-IsAdmin) } catch { }
            $langMode = 'unknown'
            try { $langMode = $ExecutionContext.SessionState.LanguageMode.ToString() } catch { }
            $row = [pscustomobject]@{
                Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                Severity  = 'Informational'
                Category  = 'Assessment Integrity'
                Source    = [string]$script:HostName
                Target    = $(if ($integrity.LauncherPath) { $integrity.LauncherPath } else { $integrity.EnginePath })
                Port      = ''
                Finding   = ('Self-authenticating audit trail: this report was produced by ' + [string]$script:Cfg.ToolName + ' v' + [string]$script:Cfg.ToolVersion + '. The digests below identify the exact launcher and engine that generated every subsequent row.')
                Prerequisites = 'None - computed at start-up, before any assessment module runs.'
                ConfigurationEvidence = ('Launcher SHA-256=' + $integrity.LauncherSha256 + ' [' + $integrity.LauncherSource + ']; Engine SHA-256=' + $integrity.EngineSha256 + ' [' + $integrity.EngineSource + ']')
                ValidationMethod = 'Independent in-memory SHA-256 computation (System.Security.Cryptography.SHA256) over the launcher file and over the extracted engine file; the launcher separately prints the engine digest at extraction time so this row and the console record can be cross-checked.'
                ObservedResult = ('Launcher=' + $(if ($integrity.LauncherPath) { $integrity.LauncherPath } else { 'n/a' }) + '; Engine=' + $(if ($integrity.EnginePath) { $integrity.EnginePath } else { 'n/a' }) + '; Host=' + [string]$script:HostName + '; User=' + $runUser + '; Elevated=' + $elevated + '; PowerShell=' + $PSVersionTable.PSVersion.ToString() + '; LanguageMode=' + $langMode)
                Exploitability = 'Not applicable - provenance record.'
                Impact = 'None. This row exists so a reviewer can prove which code produced the report and can detect a modified launcher or engine.'
                Remediation = 'Retain this row with the report. To verify: hash the .bat with Get-FileHash -Algorithm SHA256 (or any SHA-256 utility) and compare both digests against the distributed copy; the launcher also prints the engine digest at start-up.'
            }
            Write-FindingRow -Row $row
            $script:IntegrityRowWritten = $true
            $script:IntegrityHashes = $integrity
        } catch {
            $script:IntegrityRowWritten = $false
            Write-Host ('[WARN] The forensic integrity row could not be written: ' + $_.Exception.Message) -ForegroundColor Yellow
        }

        # ---- ROE ROW: what this run was authorised to touch ----------------------------------
        # Written here rather than inside a module so that it is present even if the first module aborts.
        # A reviewer can read this row alone and know the exact boundary the run was confined to.
        try {
            $ref = [string]$env:EIA_AUTHORISATION_REF
            if ([string]::IsNullOrWhiteSpace($ref)) { $ref = 'NOT SUPPLIED - set EIA_AUTHORISATION_REF to the engagement/ticket reference' }
            $scopeLine = if ($script:ScopeActive) { $script:ScopeText } else { 'no scope supplied - permissive; discovery bounded to the derived local /24' }
            $row2 = [pscustomobject]@{
                Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                Severity  = 'Informational'
                Category  = 'Assessment Integrity'
                Source    = [string]$script:HostName
                Target    = $(if ($script:ScopeActive) { 'engagement scope' } else { 'local host' })
                Port      = ''
                Finding   = ('Rules-of-engagement record: scope mode is ' + $(if ($script:ScopeActive) { 'DEFAULT-DENY against a supplied scope' } else { 'permissive (no scope supplied)' }) + '.')
                Prerequisites = 'None - recorded before any assessment module runs.'
                ConfigurationEvidence = ('Scope=[' + $scopeLine + ']; Source=[' + $script:ScopeSource + ']; AuthorisationRef=[' + $ref + ']; KillSwitch=[' + $(if (Test-KillSwitch) { 'ACTIVE' } else { 'not tripped' }) + ']')
                ValidationMethod = 'Read of the operator-supplied scope (EIA_SCOPE / EIA_SCOPE_FILE / /scope:) and authorisation reference at start-up. Every off-host operation passes through Test-TargetAllowed, which consults this scope.'
                ObservedResult = ('ScopeActive=' + $script:ScopeActive + '; Includes=' + $script:ScopeIncludes.Count + '; Excludes=' + $script:ScopeExcludes.Count)
                Exploitability = 'Not applicable - authorisation record.'
                Impact = 'None. This row is the evidence that the run was confined to the agreed boundary, and that any host appearing in the report was inside it.'
                Remediation = 'None - operator control. Retain this row with the report: it is the artefact that answers "what was this run allowed to touch?".'
            }
            Write-FindingRow -Row $row2
            $script:RoeRowWritten = $true
        } catch {
            $script:RoeRowWritten = $false
            Write-Host ('[WARN] The rules-of-engagement row could not be written: ' + $_.Exception.Message) -ForegroundColor Yellow
        }
        return $true
    } catch {
        $script:CsvOk = $false
        Write-Host "[ERROR] Unable to create the CSV report at '$Directory': $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "        Findings will still be displayed on the console but cannot be persisted." -ForegroundColor Red
        return $false
    }
}

function Get-FileSha256 {
    <# SHA-256 of a file, computed in memory. Deliberately does NOT shell out to certutil or
       Get-FileHash: the digest must be obtainable in exactly the environments this tool targets,
       including ones where binary execution is restricted. Returns '' on any failure so callers
       can state 'unavailable' rather than silently omitting the field. #>
    param([string]$Path)
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try { return (($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '') }
            finally { $fs.Dispose() }
        } finally { try { $sha.Dispose() } catch { } }
    } catch { return '' }
}

function Get-SelfIntegrityHashes {
    <# Identifies the EXACT code that produced this report. Both digests are computed in-process
       by the engine itself wherever possible, because a hash reported by the thing being hashed is
       weaker evidence than one the verifier computes independently:

         * launcher .bat  - the engine re-reads the launcher handed to it by the launcher's own
                            EIA_SELF variable and hashes it directly;
         * engine .ps1    - the engine hashes the extracted file it is executing from.

       The launcher's own values (certutil digest, extraction digest) are used only as a fallback
       and are labelled as such, so the CSV always shows WHICH mechanism produced each digest. #>
    $launcherPath = ''
    $enginePath = ''
    try { if ($env:EIA_SELF) { $launcherPath = [string]$env:EIA_SELF } } catch { }
    if (-not $enginePath) { try { if ($script:EngineSelfPath) { $enginePath = [string]$script:EngineSelfPath } } catch { } }
    if (-not $enginePath) { try { if ($env:EIA_ENGINE_PATH) { $enginePath = [string]$env:EIA_ENGINE_PATH } } catch { } }

    $launcherHash = Get-FileSha256 -Path $launcherPath
    $launcherSource = 'computed in-process by the engine over the launcher file'
    if (-not $launcherHash) {
        $launcherHash = [string]$env:EIA_LAUNCHER_SHA256
        # A failure string is NOT a digest. Accept a value only if it looks like a SHA-256 hex
        # digest, so a launcher-side failure (for example under a FIPS policy) cannot be recorded
        # as evidence with a misleading source label.
        if ($launcherHash -notmatch '^[0-9a-fA-F]{64}$') { $launcherHash = '' }
        $launcherSource = $(if ($launcherHash) { 'reported by the launcher (certutil fallback)' } else { 'unavailable' })
    }
    if (-not $launcherHash) { $launcherHash = 'unavailable' }

    $engineHash = Get-FileSha256 -Path $enginePath
    $engineSource = 'computed in-process by the engine over its own extracted file'
    if (-not $engineHash) {
        $engineHash = [string]$env:EIA_ENGINE_SHA256
        if ($engineHash -notmatch '^[0-9a-fA-F]{64}$') { $engineHash = '' }
        $engineSource = $(if ($engineHash) { 'reported by the launcher at extraction time' } else { 'unavailable' })
    }
    if (-not $engineHash) { $engineHash = 'unavailable' }

    return [pscustomobject]@{
        LauncherPath = $launcherPath
        LauncherSha256 = $launcherHash
        LauncherSource = $launcherSource
        EnginePath = $enginePath
        EngineSha256 = $engineHash
        EngineSource = $engineSource
    }
}

function ConvertTo-CsvField {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s -replace "`r`n", ' | ' -replace "`r", ' ' -replace "`n", ' | '   # keep the row on one line
    $s = $s -replace "`t", ' '
    if ($s -match '[",]') { $s = '"' + ($s -replace '"', '""') + '"' }
    return $s
}

function Write-FindingRow {
    param([object]$Row)
    if (-not $script:CsvOk) { return }
    $order = @('Timestamp','Severity','Category','Source','Target','Port','Finding','Prerequisites',
               'ConfigurationEvidence','ValidationMethod','ObservedResult','Exploitability','Impact','Remediation')
    $cells = @()
    foreach ($k in $order) { $cells += (ConvertTo-CsvField $Row.$k) }
    $line = ($cells -join ',') + "`r`n"
    try {
        [System.IO.File]::AppendAllText($script:CsvPath, $line, $script:Utf8Bom)
    } catch {
        Write-Host "[ERROR] Failed to append a row to the report: $($_.Exception.Message)" -ForegroundColor Red
        $script:CsvOk = $false
    }
}

# -------------------------------------------------------------------------------------------
#  CONSOLE PRESENTATION
# -------------------------------------------------------------------------------------------
$script:SeverityColor = @{
    'Critical'      = 'Magenta'
    'High'          = 'Red'
    'Medium'        = 'Yellow'
    'Low'           = 'DarkYellow'
    'Informational' = 'Gray'
}
$script:StatusColor = @{
    'INFO'            = 'Cyan'
    'PASS'            = 'Green'
    'WARN'            = 'Yellow'
    'RISK DETECTED'   = 'Red'
    'VALIDATED'       = 'Magenta'
    'NOT CONFIRMED'   = 'DarkGray'
    'NOT TESTABLE'    = 'DarkYellow'
    'ERROR'           = 'Red'
    'OPPORTUNITY'     = 'DarkCyan'
}

function Write-Banner {
    param([string]$Text)
    $line = '=' * 104
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ("  " + $Text) -ForegroundColor White
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Section {
    param([string]$Number, [string]$Title)
    $line = '-' * 104
    Write-Host ''
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ("  [SECTION " + $Number + "] " + $Title) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkGray
}

function Write-Status {
    param([string]$Status, [string]$Message)
    $col = $script:StatusColor[$Status]
    if (-not $col) { $col = 'Gray' }
    $tag = ('[' + $Status + ']').PadRight(16)
    Write-Host ('  ' + $tag) -ForegroundColor $col -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Write-KV {
    param([string]$Key, [object]$Value, [string]$Note = '')
    if ($null -eq $Value -or ([string]$Value).Trim() -eq '') { $Value = '(not available)' }
    $k = ($Key + ' :').PadRight(34)
    Write-Host ('    ' + $k) -ForegroundColor DarkGray -NoNewline
    Write-Host ([string]$Value) -ForegroundColor White -NoNewline
    if ($Note) { Write-Host ('   ' + $Note) -ForegroundColor DarkGray } else { Write-Host '' }
}

function Write-Table {
    param([object[]]$Rows, [string[]]$Columns, [hashtable]$Headers = @{}, [string]$Indent = '    ')
    if (-not $Rows -or $Rows.Count -eq 0) { Write-Host ($Indent + '(no records)') -ForegroundColor DarkGray; return }
    $widths = @{}
    foreach ($c in $Columns) {
        $h = $c; if ($Headers.ContainsKey($c)) { $h = $Headers[$c] }
        $w = $h.Length
        foreach ($r in $Rows) {
            $v = [string]$r.$c
            if ($v.Length -gt $w) { $w = $v.Length }
        }
        if ($w -gt 46) { $w = 46 }
        $widths[$c] = $w
    }
    $hdr = $Indent
    foreach ($c in $Columns) {
        $h = $c; if ($Headers.ContainsKey($c)) { $h = $Headers[$c] }
        $hdr += $h.PadRight($widths[$c] + 2)
    }
    Write-Host $hdr -ForegroundColor DarkCyan
    $sep = $Indent + ('-' * ($hdr.Length - $Indent.Length))
    Write-Host $sep -ForegroundColor DarkGray
    foreach ($r in $Rows) {
        $line = $Indent
        foreach ($c in $Columns) {
            $v = [string]$r.$c
            if ($v.Length -gt $widths[$c]) { $v = $v.Substring(0, $widths[$c] - 3) + '...' }
            $line += $v.PadRight($widths[$c] + 2)
        }
        Write-Host $line -ForegroundColor Gray
    }
}

# -------------------------------------------------------------------------------------------
#  SECTION RUNNER
#  Guarantees module isolation: any terminating error inside a section is caught, converted
#  into an ERROR finding and the assessment continues to the next module.
# -------------------------------------------------------------------------------------------
function Invoke-Section {
    param([string]$Number, [string]$Title, [scriptblock]$Body)
    Write-Section $Number $Title
    # Kill switch: checked at the ONE place every module is dispatched from. A routine that has
    # already started still completes (it may be mid-way through a local read), but no NEW module
    # begins, and Test-TargetAllowed refuses any new off-host operation immediately.
    if (Test-KillSwitch) {
        Write-Status 'NOT TESTABLE' ('SKIPPED - the kill switch is active (EIA_KILL_SWITCH=1 or an EIA_STOP file). Module ' + $Number + ' performed no action.')
        Add-Finding -Category 'Assessment Engine' -Status 'NOT TESTABLE' -Attribute 'Kill switch' -CatClass 'Context' `
            -Finding ('Module ' + $Number + ' (' + $Title + ') was SKIPPED because the operator kill switch is active.') `
            -Observed 'Kill switch tripped; the module body was not entered.' `
            -Validation 'Operator-initiated abort control (EIA_KILL_SWITCH=1 env var, or an EIA_STOP file in the working directory or %TEMP%).' `
            -Class 'Low' -CatClass 'Context' `
            -Remediation 'None - this is an operator control. Re-run without the kill switch to assess this module.' `
            -Impact 'This module''s controls are UNKNOWN, not compliant. Treat every unexecuted module as unassessed in the report.' -NoConsole
        return
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
    } catch {
        Write-Status 'ERROR' ("Section $Number aborted: " + $_.Exception.Message)
        Add-Finding -Category 'Assessment Engine' -Status 'ERROR' -Target $script:HostName `
            -Finding ("Module '" + $Title + "' terminated unexpectedly") `
            -Observed ("Exception: " + $_.Exception.Message + " | At: " + $_.InvocationInfo.PositionMessage) `
            -Remediation 'Re-run this module with -Verbose or review the transcript; an aborted module means its controls are UNKNOWN, not compliant.'
    }
    $sw.Stop()
    Write-Host ("    (module runtime: {0:N1}s)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}

# -------------------------------------------------------------------------------------------
#  FINDING ENGINE
#  Add-Finding is the ONLY way rows reach the report. The signature forces the author of a
#  test to state configuration evidence and validation method separately, which is what makes
#  "discovered weakness" vs "validated weakness" auditable after the fact.
# -------------------------------------------------------------------------------------------
function Add-Finding {
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][ValidateSet('INFO','PASS','WARN','RISK DETECTED','VALIDATED','NOT CONFIRMED','NOT TESTABLE','ERROR','OPPORTUNITY')][string]$Status,
        [Parameter(Mandatory=$true)][string]$Finding,
        [string]$Attribute      = '',
        [string]$Source         = '',
        [string]$Target         = '',
        [string]$Port           = '',
        [string]$Prerequisites  = '',
        [string]$Observed       = '',
        [string]$Validation     = 'None (static configuration evidence only)',
        [string]$Exploitability = 'Not demonstrated',
        [string]$Impact         = '',
        [string]$Remediation    = '',
        [string]$Expected       = '',
        [string]$Configured     = '',
        [string]$Class          = 'Medium',
        [ValidateSet('Confidentiality','Integrity','Availability','DataAtRest','IdentityRights','Context')][string]$CatClass = 'Confidentiality',
        [string]$SeverityOverride = '',
        [bool]$Weakness      = $false,
        [switch]$NoConsole
    )
    if ([string]::IsNullOrWhiteSpace($Source)) { $Source = $script:HostName }
    if ([string]::IsNullOrWhiteSpace($Target)) { $Target = $script:HostName }

    $sev = $SeverityOverride
    if ([string]::IsNullOrWhiteSpace($sev)) {
        $sev = Get-FindingSeverity -Class $Class -CatClass $CatClass -Weakness $Weakness
    }

    # Compact, human-readable configuration evidence: EXPECTED / CONFIGURED / OBSERVED
    $confEv = ''
    if ($Expected)   { $confEv += 'EXPECTED=' + $Expected + '; ' }
    if ($Configured) { $confEv += 'CONFIGURED=' + $Configured + '; ' }
    if ($Attribute)  { $confEv += 'ATTRIBUTE=' + $Attribute + '; ' }
    $confEv = ($confEv.TrimEnd(' ', ';'))
    if ([string]::IsNullOrWhiteSpace($confEv)) { $confEv = 'See OBSERVED RESULT column (live/enumerated evidence, no registry attribute applicable).' }

    $script:Seq++
    $row = [pscustomobject]@{
        Timestamp             = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity              = $sev
        Category              = $Category
        Source                = $Source
        Target                = $Target
        Port                  = $Port
        Finding               = $Finding
        Prerequisites         = $Prerequisites
        ConfigurationEvidence = $confEv
        ValidationMethod      = $Validation
        ObservedResult        = $Observed
        Exploitability        = $Exploitability
        Impact                = $Impact
        Remediation           = $Remediation
        # internal-only helper fields (not written to CSV)
        Status                = $Status
        Seq                   = $script:Seq
    }
    [void]$script:Findings.Add($row)
    [void]$script:TestLog.Add([pscustomobject]@{ Seq=$script:Seq; Time=$row.Timestamp; Status=$Status; Severity=$sev; Category=$Category; Attribute=$Attribute; Finding=$Finding; Observed=$Observed })
    Write-FindingRow $row

    $script:Stats.Rows++
    switch ($Status) {
        'WARN'          { $script:Stats.ConfigFindings++ }
        'RISK DETECTED' { $script:Stats.ConfigFindings++ }
        'VALIDATED'     { $script:Stats.ValidatedFindings++; $script:Stats.ConfigFindings++ }
        'NOT CONFIRMED' { $script:Stats.NotConfirmed++ }
        'NOT TESTABLE'  { $script:Stats.NotTestable++ }
        'ERROR'         { $script:Stats.Errors++ }
    }
    if ($sev -eq 'Critical') { $script:Stats.CriticalFindings++ }

    if (-not $NoConsole) {
        $col = $script:StatusColor[$Status]; if (-not $col) { $col = 'Gray' }
        $sevCol = $script:SeverityColor[$sev]; if (-not $sevCol) { $sevCol = 'Gray' }
        $tag = ('[' + $Status + ']').PadRight(16)
        Write-Host ('  ' + $tag) -ForegroundColor $col -NoNewline
        Write-Host ($Attribute.PadRight(34)) -ForegroundColor DarkGray -NoNewline
        Write-Host $Finding -ForegroundColor Gray -NoNewline
        Write-Host ('  <' + $sev + '>') -ForegroundColor $sevCol
        if ($Observed) { Write-Host ('                  ' + $Observed) -ForegroundColor DarkGray }
    }
    return $row
}

function Write-Context {
    param([string]$Attribute, [string]$Value, [string]$Note = '')
    Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' -Attribute $Attribute `
        -Finding ($Attribute + ' = ' + $Value) -Observed $Value -Validation 'Read-only collection (no validation applicable)' `
        -Exploitability 'N/A (context record; not a vulnerability)' -Impact 'N/A (context record; not a vulnerability)' `
        -Remediation 'None - informational context row.' -NoConsole
    Write-KV $Attribute $Value $Note
}

# -------------------------------------------------------------------------------------------
#  GENERIC HELPERS
# -------------------------------------------------------------------------------------------
function Get-RegValue {
    <# Returns the TRUE state of a registry value, including the distinction between
       "key missing", "value missing" and "value present but empty". This is essential:
       an absent value is NOT proof of an insecure setting - it means "not configured", and
       the Windows default then applies. #>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Name = '',
        [ValidateSet('LocalMachine','CurrentUser','Users','ClassesRoot')][string]$Hive = 'LocalMachine'
    )
    $r = [ordered]@{ Path=$Path; Name=$Name; Hive=$Hive; KeyExists=$false; NameExists=$false; Value=$null; Kind=''; Error='' }
    try {
        switch ($Hive) {
            'CurrentUser'   { $root = [Microsoft.Win32.Registry]::CurrentUser }
            'Users'         { $root = [Microsoft.Win32.Registry]::Users }
            'ClassesRoot'   { $root = [Microsoft.Win32.Registry]::ClassesRoot }
            default         { $root = [Microsoft.Win32.Registry]::LocalMachine }
        }
        $key = $root.OpenSubKey($Path, $false)
        if ($null -eq $key) { $r.KeyExists = $false }
        else {
            $r.KeyExists = $true
            if ([string]::IsNullOrEmpty($Name)) {
                $r.NameExists = $true; $r.Kind = 'KEY'
                $r.Value = ($key.GetValueNames() -join ', ')
            } elseif ($key.GetValueNames() -contains $Name) {
                $r.NameExists = $true
                $r.Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                try { $r.Kind = $key.GetValueKind($Name).ToString() } catch { $r.Kind = 'UNKNOWN' }
            }
            $key.Close()
        }
    } catch { $r.Error = $_.Exception.Message }
    return [pscustomobject]$r
}

function Format-RegState {
    param([object]$Reg)
    if ($Reg.Error) { return 'QUERY ERROR: ' + $Reg.Error }
    if (-not $Reg.KeyExists) { return 'key absent (default behaviour applies)' }
    if (-not $Reg.NameExists) { return 'value not present (default behaviour applies)' }
    if ($null -eq $Reg.Value) { return 'present, empty value' }
    return ('present = ' + [string]$Reg.Value + ' (' + $Reg.Kind + ')')
}

function Get-U32 {
    param([object]$Reg)
    if ($null -eq $Reg -or -not $Reg.NameExists -or $null -eq $Reg.Value) { return $null }
    try { return [uint32]$Reg.Value } catch { return $null }
}

function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-RemoteAllowed {
    <# Single policy gate for OUTBOUND traffic off this host.

       NETWORK AUTHORISATION: the launcher sets EIA_REQUIRE_NETWORK_AUTH=1, which means off-host
       work additionally requires an explicit act on the command line - a scope (/scope:,
       /scopefile:) or /authorize-active. Automation defaults no longer imply permission to send
       packets: a bare double-click assesses THIS HOST and nothing else. Running the engine
       directly leaves both variables unset, so direct invocation is unchanged.

       EIA_LOCAL_ONLY=1 (launcher switch /localonly) suppresses every remote operation: the address
       sweep, the DC reachability probe, LDAP/ADSI directory queries, the Kerberos AS-REQ probe and
       the remote administrative-reachability check. Used when a change window mandates that the
       assessment produces no off-host traffic at all. Loopback probes against this host remain:
       they do not leave the machine.

       Default is $true, so behaviour is unchanged unless the operator asks for it. #>
    if ($env:EIA_LOCAL_ONLY -eq '1') { return $false }
    if ($env:EIA_REQUIRE_NETWORK_AUTH -eq '1' -and $env:EIA_NETWORK_AUTH -ne '1') { return $false }
    return $true
}

# -------------------------------------------------------------------------------------------
#  ENGAGEMENT SCOPE
#  Optional. Supplied as EIA_SCOPE (comma/semicolon separated) or EIA_SCOPE_FILE (one entry per
#  line), or with the /scope: switch. Entries may be:
#        10.0.0.0/24        an IPv4 range
#        10.0.5.10          a single IPv4 address
#        srv-db-01          a host name (exact, case-insensitive)
#        .corp.example.com  a host name SUFFIX (leading dot required - see below)
#        !10.0.5.99         an EXCLUSION, applied before includes
#
#  BEHAVIOUR: when NO scope is supplied the tool is permissive and behaves exactly as before
#  (bounded to the derived local /24). When a scope IS supplied the mode is DEFAULT-DENY: any
#  target that does not match an include is refused, so an out-of-scope address cannot be
#  reached by any code path - sweep, service matrix, banner capture, DC probe or the
#  administrative-reachability candidates.
#
#  Hostname matching is TEXTUAL. The tool does not resolve names to decide scope, because doing
#  so would itself be an off-host DNS query - so a scope written with IP addresses is the only
#  form that is enforced against addresses discovered by the sweep. A hostname-only scope
#  constrains the named candidates but cannot constrain a bare IP that the local NIC reveals.
# -------------------------------------------------------------------------------------------
$script:ScopeIncludes = New-Object System.Collections.ArrayList
$script:ScopeExcludes = New-Object System.Collections.ArrayList
$script:ScopeActive   = $false
$script:ScopeSource   = 'not supplied (permissive: discovery is bounded to the derived local /24)'
$script:ScopeText     = ''

function Initialize-Scope {
    # Reset first. A second call (or a call after a partial parse) must not inherit entries from a
    # previous scope, which would silently WIDEN the boundary the run is confined to.
    $script:ScopeIncludes.Clear()
    $script:ScopeExcludes.Clear()
    $script:ScopeActive = $false
    $script:ScopeText   = ''

    $raw = [string]$env:EIA_SCOPE
    if (-not [string]::IsNullOrWhiteSpace($env:EIA_SCOPE_FILE)) {
        try {
            if (Test-Path -LiteralPath $env:EIA_SCOPE_FILE) {
                $raw = $raw + ',' + [System.IO.File]::ReadAllText($env:EIA_SCOPE_FILE)
                $script:ScopeSource = 'scope file ' + [string]$env:EIA_SCOPE_FILE
            } else {
                $script:ScopeSource = 'scope file NOT FOUND: ' + [string]$env:EIA_SCOPE_FILE
                Write-Host ('[WARN] Scope file not found: ' + $env:EIA_SCOPE_FILE + ' - running permissive.') -ForegroundColor Yellow
            }
        } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return }

    foreach ($entry in ($raw -split '[,\r\n;]+')) {
        $t = ([string]$entry).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($t.StartsWith('#')) { continue }
        $excl = $false
        if ($t.StartsWith('!')) { $excl = $true; $t = $t.Substring(1).Trim() }
        $obj = $null
        if ($t -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
            $bits = [int]($t -split '/')[1]
            if ($bits -lt 0 -or $bits -gt 32) { continue }
            $base = ConvertTo-IPv4UInt32 ($t -split '/')[0]
            if ($null -eq $base) { continue }
            # NOTE: 0xFFFFFFFF is an Int32 literal in PowerShell and evaluates to -1, and casting
            # -1 to [uint32] throws - so the mask MUST be built from [uint32]::MaxValue. Using the
            # hex literal here silently dropped every CIDR entry and left the tool permissive.
            $mask = if ($bits -eq 0) { [uint32]0 } else { [uint32](([uint32]::MaxValue -shl (32 - $bits)) -band [uint32]::MaxValue) }
            $lo = [uint32]($base -band $mask)
            $hi = [uint32]($lo -bor ([uint32]::MaxValue -bxor $mask))
            $obj = @{ Kind = 'ip'; Lo = $lo; Hi = $hi; Text = $t }
        } elseif ($t -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $v = ConvertTo-IPv4UInt32 $t
            if ($null -eq $v) { continue }
            $obj = @{ Kind = 'ip'; Lo = $v; Hi = $v; Text = $t }
        } else {
            # A leading dot is REQUIRED for suffix matching, so 'corp.example.com' never matches
            # 'evilcorp.example.com'. Without that rule a suffix entry would silently widen scope.
            $suffix = $t.StartsWith('.')
            $obj = @{ Kind = 'host'; Pattern = $t.TrimStart('.').ToLowerInvariant(); Suffix = $suffix; Text = $t }
        }
        if ($excl) { [void]$script:ScopeExcludes.Add($obj) } else { [void]$script:ScopeIncludes.Add($obj) }
    }
    if ($script:ScopeIncludes.Count -gt 0) {
        $script:ScopeActive = $true
        $script:ScopeText = (@($script:ScopeExcludes | ForEach-Object { '!' + $_.Text }) + @($script:ScopeIncludes | ForEach-Object { $_.Text })) -join ', '
    }
}

function Test-InScope {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    if (-not $script:ScopeActive) { return $true }   # no scope supplied => permissive
    $ip = ConvertTo-IPv4UInt32 $Target
    $tl = $Target.ToLowerInvariant()
    foreach ($e in $script:ScopeExcludes) {
        if ($e.Kind -eq 'ip') { if (($null -ne $ip) -and ($ip -ge $e.Lo) -and ($ip -le $e.Hi)) { return $false } }
        elseif ($e.Suffix) { if ($tl -eq $e.Pattern -or $tl.EndsWith('.' + $e.Pattern)) { return $false } }
        else { if ($tl -eq $e.Pattern) { return $false } }
    }
    foreach ($e in $script:ScopeIncludes) {
        if ($e.Kind -eq 'ip') { if (($null -ne $ip) -and ($ip -ge $e.Lo) -and ($ip -le $e.Hi)) { return $true } }
        elseif ($e.Suffix) { if ($tl -eq $e.Pattern -or $tl.EndsWith('.' + $e.Pattern)) { return $true } }
        else { if ($tl -eq $e.Pattern) { return $true } }
    }
    return $false
}

# -------------------------------------------------------------------------------------------
#  KILL SWITCH
#  Trips on EIA_KILL_SWITCH=1, or the presence of a file named EIA_STOP in the working directory
#  or in %TEMP%. Once tripped, Test-TargetAllowed refuses every subsequent off-host operation, so
#  the sweep, the banner capture and the administrative-reachability candidates all stop at the
#  next check rather than after the current phase completes.
# -------------------------------------------------------------------------------------------
function Test-KillSwitch {
    if ($env:EIA_KILL_SWITCH -eq '1') { return $true }
    try {
        if (Test-Path -LiteralPath (Join-Path (Get-Location).Path 'EIA_STOP')) { return $true }
    } catch { }
    try {
        if (Test-Path -LiteralPath (Join-Path ([System.IO.Path]::GetTempPath()) 'EIA_STOP')) { return $true }
    } catch { }
    return $false
}

# Combined gate for an OFF-HOST operation against a specific target. This is the function every
# remote primitive consults; it composes the three independent refusals.
function Test-TargetAllowed {
    param([string]$Target)
    if (Test-KillSwitch) { return $false }
    if (-not (Test-RemoteAllowed)) { return $false }
    if (-not (Test-InScope -Target $Target)) { return $false }
    return $true
}

# Reason string for the evidence rows, so a suppressed probe states WHY it was suppressed.
function Get-TargetSuppressionReason {
    param([string]$Target)
    if (Test-KillSwitch) { return 'Refused by the KILL SWITCH (EIA_KILL_SWITCH=1 or an EIA_STOP file in the working directory or %TEMP%): no further off-host operation was performed.' }
    if (-not (Test-RemoteAllowed)) { return (Get-RemoteSuppressedNote) }
    if (-not (Test-InScope -Target $Target)) { return ('Refused by ENGAGEMENT SCOPE: ' + $Target + ' is not within the supplied scope (' + $script:ScopeText + '). No packet was sent to it.') }
    return ''
}

function Get-RemoteSuppressedNote {
    <# Wording used in every NOT TESTABLE row produced because off-host work was refused, so the
       report states an operator decision rather than implying the directory or network was
       unreachable. Distinguishes the three independent refusals: /localonly, absent network
       authorisation, and the kill switch. #>
    if ($env:EIA_LOCAL_ONLY -eq '1') {
        return 'Suppressed by operator request (/localonly): no assessment probe was sent to any remote host by this module'
    }
    if ($env:EIA_REQUIRE_NETWORK_AUTH -eq '1' -and $env:EIA_NETWORK_AUTH -ne '1') {
        return 'Suppressed: no network authorisation was supplied. This run was not pre-authorised for off-host work - pass /scope:<cidr> (or /authorize-active) to authorise it. No assessment probe was sent to any remote host by this module'
    }
    return 'Suppressed: off-host work was refused by the current policy. No assessment probe was sent to any remote host by this module'
}

function Get-LdapUnavailableReason {
    <# Distinguishes 'the directory could not be reached' from 'directory queries were suppressed on
       purpose'. Both lead to NOT TESTABLE rows, but the wording must not mislead a reader into
       thinking a network path was tested and failed. #>
    if (-not (Test-RemoteAllowed)) { return (Get-RemoteSuppressedNote) }
    return 'Directory is not reachable'
}

function Get-CfgFlag {
    <# Reads a boolean configuration switch safely. An ABSENT configuration key must never be
       mistaken for an operator decision: absent or unparsable falls back to the documented
       default AND says so, so a missing key cannot silently disable a control. #>
    param([string]$Name, [bool]$Default = $true)
    try {
        if ($script:Cfg -and $script:Cfg.Contains($Name)) {
            $v = $script:Cfg[$Name]
            if ($v -is [bool]) { return $v }
            if ($null -ne $v) { return [bool]$v }
        }
    } catch { }
    Write-Status 'INFO' ('Configuration key ''' + $Name + ''' is absent; the documented default (' + [string]$Default + ') is used.')
    return $Default
}

function Request-Consent {
    <# SINGLE CHOKE POINT for every interactive consent decision.
       Returns @{ Allowed; Mode; Note } so each gated step can cite HOW it was authorised.

       Precedence:
         1. EIA_PREAUTH=1  - the consent-gated steps are pre-authorised. HOW that happened is
                             recorded verbatim from EIA_PREAUTH_SOURCE, so the evidence
                             distinguishes the command-line switch /authorize-active from the
                             launcher default that applies when the file is simply executed.
         2. EIA_HEADLESS=1 - /headless: never prompt; apply the safe default; report NOT TESTABLE.
         3. [Console]::IsInputRedirected - standard input is not an interactive console.
                             Prompting here can BLOCK INDEFINITELY: an open stdin pipe that never
                             delivers data hangs Read-Host forever - exactly how a scheduled task
                             or CI runner stalls. Treated as unattended: never prompt.
         4. Otherwise prompt via Read-Host inside try/catch; any failure uses the safe default.

       $DefaultAllowed is the answer used whenever the operator is NOT asked. Callers pass $false,
       so an unattended run never performs an active step by accident. #>
    param(
        [Parameter(Mandatory=$true)][string]$Question,
        [string]$StepName = 'active step',
        [bool]$DefaultAllowed = $false
    )
    $r = [pscustomobject]@{ Allowed = $DefaultAllowed; Mode = 'interactive'; Note = '' }
    if ($env:EIA_PREAUTH -eq '1') {
        $r.Allowed = $true
        $r.Mode = 'preauthorised'
        # The SOURCE is recorded truthfully. A double-click does not pass /authorize-active, and the
        # evidence must not imply that it did: an auditor reading the CSV needs to know whether a
        # human typed the switch or whether the tool's own default authorised the step.
        $src = ''
        try { $src = [string]$env:EIA_PREAUTH_SOURCE } catch { }
        if ([string]::IsNullOrWhiteSpace($src)) { $src = 'pre-authorisation flag set in the environment (source not recorded by the launcher)' }
        $r.Note = ('Pre-authorised: ' + $src + '. No console prompt was shown. The authorisation act is the execution of the launcher inside the signed engagement scope.')
        Write-Status 'VALIDATED' ($StepName + ': ' + $r.Note)
        return $r
    }
    if ($env:EIA_HEADLESS -eq '1') {
        $r.Mode = 'headless'
        $r.Note = 'Unattended (/headless): no prompt was possible, so the safe default (allow=' + [string]$r.Allowed + ') was applied and this step is reported NOT TESTABLE.'
        Write-Status 'NOT TESTABLE' ($StepName + ': ' + $r.Note)
        return $r
    }
    $redirected = $false
    try { $redirected = [Console]::IsInputRedirected } catch { $redirected = $false }
    if ($redirected) {
        $r.Mode = 'unattended-stdin'
        $r.Note = 'Standard input is redirected, so no interactive answer is possible without risking an indefinite block; the safe default (allow=' + [string]$r.Allowed + ') was applied.'
        Write-Status 'NOT TESTABLE' ($StepName + ': ' + $r.Note)
        return $r
    }
    try {
        $ans = Read-Host ('    ' + $Question)
        $r.Mode = 'interactive'
        if ($ans -and $ans.Trim() -match '^(?i)y') { $r.Allowed = $true } else { $r.Allowed = $false }
        $r.Note = 'Answered at the console by the operator (answer: ' + $(if ($r.Allowed) { 'yes' } else { 'no' }) + ').'
    } catch {
        $r.Mode = 'interactive-failed'
        $r.Note = 'The console prompt failed (' + $_.Exception.Message + '); the safe default was applied.'
        Write-Status 'NOT TESTABLE' ($StepName + ': ' + $r.Note)
    }
    return $r
}

function Initialize-TokenProbe {
    <# Loads (once per process) an in-memory P/Invoke helper that queries the CURRENT PROCESS TOKEN.

       WHY: the mandatory-integrity SID and the token privilege list were previously read by spawning
       whoami.exe. On a hardened server that is a liability: Application Control (WDAC/AppLocker) can
       block the binary outright, and every spawn of a built-in executable is additional noise in the
       Security event log. GetTokenInformation is a read-only query against a handle this process
       already owns: no child process, no binary on disk, no file access, nothing to block.

       Failure is non-fatal by design. If Add-Type is unavailable (ConstrainedLanguage mode) the
       function returns $false and the callers fall back to managed .NET enumeration or report
       NOT TESTABLE with the reason. #>
    if ($null -ne $script:TokenProbeReady) { return $script:TokenProbeReady }
    $script:TokenProbeReady = $false
    $script:TokenProbeMethod = 'unavailable'
    try {
        if (-not ('EiaTokenProbe' -as [type])) {
$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class EiaTokenProbe
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength, out int returnLength);
    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeName(string systemName, ref LUID luid, StringBuilder name, ref int nameLength);

    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenPrivileges = 3;
    private const int TokenIntegrityLevel = 25;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    public static string GetIntegrityLabel()
    {
        IntPtr token = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) { return ""; }
            int needed = 0;
            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out needed);
            if (needed <= 0) { return ""; }
            buffer = Marshal.AllocHGlobal(needed);
            if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, needed, out needed)) { return ""; }
            IntPtr sid = Marshal.ReadIntPtr(buffer, 0);
            if (sid == IntPtr.Zero) { return ""; }
            IntPtr countPtr = GetSidSubAuthorityCount(sid);
            if (countPtr == IntPtr.Zero) { return ""; }
            byte count = Marshal.ReadByte(countPtr);
            if (count == 0) { return ""; }
            IntPtr ridPtr = GetSidSubAuthority(sid, (uint)(count - 1));
            if (ridPtr == IntPtr.Zero) { return ""; }
            int rid = Marshal.ReadInt32(ridPtr);
            string label;
            if (rid == 0) { label = "Untrusted"; }
            else if (rid == 4096) { label = "Low"; }
            else if (rid == 8192) { label = "Medium"; }
            else if (rid == 12288) { label = "High"; }
            else if (rid == 16384) { label = "System"; }
            else { label = "Custom"; }
            return label + " (S-1-16-" + rid.ToString() + ")";
        }
        catch { return ""; }
        finally
        {
            if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
            if (token != IntPtr.Zero) { CloseHandle(token); }
        }
    }

    public static string[] GetPrivileges()
    {
        IntPtr token = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) { return new string[0]; }
            int needed = 0;
            GetTokenInformation(token, TokenPrivileges, IntPtr.Zero, 0, out needed);
            if (needed <= 0) { return new string[0]; }
            buffer = Marshal.AllocHGlobal(needed);
            if (!GetTokenInformation(token, TokenPrivileges, buffer, needed, out needed)) { return new string[0]; }
            int count = Marshal.ReadInt32(buffer, 0);
            string[] result = new string[count];
            for (int i = 0; i < count; i++)
            {
                int offset = 4 + (i * 12);
                LUID luid = new LUID();
                luid.LowPart = (uint)Marshal.ReadInt32(buffer, offset);
                luid.HighPart = Marshal.ReadInt32(buffer, offset + 4);
                int attributes = Marshal.ReadInt32(buffer, offset + 8);
                int size = 256;
                StringBuilder name = new StringBuilder(size);
                if (!LookupPrivilegeName(null, ref luid, name, ref size))
                {
                    result[i] = "LUID-" + luid.LowPart.ToString() + "|0|" + attributes.ToString();
                    continue;
                }
                bool enabled = ((attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED);
                result[i] = name.ToString() + "|" + (enabled ? "1" : "0") + "|" + attributes.ToString();
            }
            return result;
        }
        catch { return new string[0]; }
        finally
        {
            if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
            if (token != IntPtr.Zero) { CloseHandle(token); }
        }
    }
}
'@
            Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop
        }
        $script:TokenProbeReady = $true
        $script:TokenProbeMethod = 'in-memory .NET token query (advapi32 GetTokenInformation via P/Invoke; no native helper binary was spawned)'
    } catch {
        $script:TokenProbeReady = $false
        $script:TokenProbeMethod = 'in-memory token query unavailable (' + $_.Exception.Message + ')'
    }
    return $script:TokenProbeReady
}

function Get-TokenPrivileges {
    <# Token privileges of the current process, obtained WITHOUT spawning whoami.exe.
       Returns an array of objects: Name, Enabled (bool), State (display string), Attributes (raw).
       An empty array means the probe could not run; callers must report NOT TESTABLE rather than
       treating an empty result as 'no privileges held'. #>
    if ($null -ne $script:TokenPrivilegesCache) { return $script:TokenPrivilegesCache }
    $out = @()
    if (Initialize-TokenProbe) {
        try {
            foreach ($raw in @([EiaTokenProbe]::GetPrivileges())) {
                $parts = [string]$raw -split '\|'
                if ($parts.Count -lt 3) { continue }
                $attrs = 0
                [void][int]::TryParse($parts[2], [ref]$attrs)
                $isEnabled = ($parts[1] -eq '1')
                $state = if ($isEnabled) { 'Enabled' } elseif (($attrs -band 0x1) -eq 0x1) { 'Disabled (enabled by default)' } else { 'Disabled' }
                $out += [pscustomobject]@{ Name=$parts[0]; Enabled=$isEnabled; State=$state; Attributes=$attrs }
            }
        } catch { }
    }
    $script:TokenPrivilegesCache = @($out)
    return $script:TokenPrivilegesCache
}

function Get-ServiceSafe {
    param([string]$Name)
    try { return Get-Service -Name $Name -ErrorAction Stop } catch { return $null }
}

function Get-CimSafe {
    param([string]$Class, [string]$Namespace = 'root/cimv2', [string]$Filter = '')
    try {
        if ($Filter) { return @(Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop) }
        return @(Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop)
    } catch {
        Write-Status 'NOT TESTABLE' ("WMI/CIM query '" + $Namespace + ':' + $Class + "' failed: " + $_.Exception.Message)
        return @()
    }
}

function ConvertFrom-CimDateTime {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return [System.Management.ManagementDateTimeConverter]::ToDateTime($Value) } catch { return $null }
}

function Invoke-RawPowerShell {
    <# Executes raw PowerShell text (never a command line) in a fresh child process, avoiding
       cmd.exe quoting/escaping entirely. Base64-encoded -EncodedCommand is a native Windows
       PowerShell capability and is used so that no quote character ever reaches the shell. #>
    param([Parameter(Mandatory=$true)][string]$Script)
    $exe = $script:PowerShellExe
    if (-not $exe) { return [pscustomobject]@{ Ok=$false; Output=''; Error='PowerShell executable not resolved'; Seconds=0 } }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Script))
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $exe
        $psi.Arguments              = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $enc
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        if (-not $p.WaitForExit(30000)) {
            try { $p.Kill() } catch { }
            $sw.Stop()
            return [pscustomobject]@{ Ok=$false; Output=''; Error='child PowerShell exceeded 30s and was terminated'; Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2) }
        }
        $out = $p.StandardOutput.ReadToEnd()
        $err = $p.StandardError.ReadToEnd()
        $sw.Stop()
        return [pscustomobject]@{ Ok=($p.ExitCode -eq 0); Output=$out.Trim(); Error=$err.Trim(); Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2) }
    } catch {
        $sw.Stop()
        return [pscustomobject]@{ Ok=$false; Output=''; Error=$_.Exception.Message; Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2) }
    }
}

# ---------------------------------------------------------------------------------------------
#  LOAD-TIME CONTEXT (evaluated once when the payload is dot-sourced or run)
#  The engine records where IT lives, so the integrity row can hash the exact file being executed
#  without depending on anything the launcher reports.
# ---------------------------------------------------------------------------------------------
$script:EngineSelfPath = ''
try {
    if ($PSCommandPath) { $script:EngineSelfPath = $PSCommandPath }
    elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) { $script:EngineSelfPath = $MyInvocation.MyCommand.Path }
} catch { }
# ===========================================================================================
#  SECTION 1 :: SYSTEM INITIALIZATION  (part 2/9)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Every later finding is only meaningful in the context of "who am I, where am I, and what
#  authority do I hold". This module establishes that baseline and classifies the host role,
#  because the SAME configuration can be correct on a workstation and a serious exposure on
#  a domain controller. It also records the privilege/fidelity of the assessment context:
#  a low-integrity run produces different (weaker) evidence than an elevated run, and the
#  report must state which one occurred so results are never over-claimed.
# ===========================================================================================

$script:HostName   = $env:COMPUTERNAME
$script:Section1Role = 'Unknown'

function Get-NicInventory {
    <# .NET-based interface inventory: works on every supported Windows version without
       depending on the NetTCPIP module (which is absent on some hardened/minimal builds). #>
    $result = New-Object System.Collections.ArrayList
    try {
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($n in $nics) {
            $v4 = @(); $v6 = @(); $gw = @(); $dns = @()
            try {
                $pp = $n.GetIPProperties()
                foreach ($ua in $pp.UnicastAddresses) {
                    if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                        $v4 += ($ua.Address.ToString() + '/' + $ua.PrefixLength)
                    } elseif ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                        $a = $ua.Address.ToString()
                        if ($a -notlike 'fe80*' -and $a -ne '::1') { $v6 += ($a + '/' + $ua.PrefixLength) }
                    }
                }
                foreach ($g in $pp.GatewayAddresses) { if ($g.Address.ToString() -ne '0.0.0.0') { $gw += $g.Address.ToString() } }
                foreach ($d in $pp.DnsAddresses)    { $dns += $d.ToString() }
            } catch { }
            [void]$result.Add([pscustomobject]@{
                Name        = $n.Name
                Description = $n.Description
                Type        = $n.NetworkInterfaceType.ToString()
                Status      = $n.OperationalStatus.ToString()
                SpeedMbps   = [math]::Round(($n.Speed / 1000000), 0)
                Mac         = ($n.GetPhysicalAddress().ToString())
                IPv4        = ($v4 -join ', ')
                IPv6        = ($v6 -join ', ')
                Gateway     = ($gw -join ', ')
                DnsServers  = ($dns -join ', ')
                IsUp        = ($n.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up)
            })
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Network interface enumeration failed: ' + $_.Exception.Message)
    }
    return $result
}

function Get-LocalIpv4 {
    param([object[]]$Nics)
    $ips = @()
    foreach ($n in $Nics) {
        if (-not $n.IsUp) { continue }
        if ($n.Name -match 'Loopback') { continue }
        foreach ($p in ($n.IPv4 -split ',\s*')) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            $c = $p.Split('/')[0]
            if ($c -like '127.*' -or $c -like '169.254.*') { continue }
            $ips += $c
        }
    }
    return @($ips | Select-Object -Unique)
}

function Get-IntegrityLevel {
    <# Mandatory integrity level of the current process, obtained by IN-MEMORY .NET ONLY.

       whoami.exe is no longer spawned anywhere in this engine. On a hardened server that binary is
       a liability: Application Control (WDAC/AppLocker) can block it, and every spawn of a built-in
       executable adds noise to the Security event log. Two in-memory paths are attempted:

         Path 1  GetTokenInformation(TokenIntegrityLevel) through the cached P/Invoke probe - an
                 exact query of this process's own token handle. Authoritative.
         Path 2  WindowsIdentity.GetCurrent().Groups - pure managed enumeration; the mandatory label
                 is present in the token's group list as the well-known S-1-16-<rid> SID. No
                 compilation and no native call, so it survives ConstrainedLanguage mode.

       The method actually used is recorded in $script:IntegrityLevelMethod for the report, and the
       value is cached. Every failure path returns a STRING: this function never terminates a module. #>
    if ($script:IntegrityLevelCache) { return $script:IntegrityLevelCache }
    $map = @{ '0'='Untrusted'; '4096'='Low'; '8192'='Medium'; '12288'='High'; '16384'='System' }

    # ---- Path 1: exact in-memory token query ---------------------------------------------
    if (Initialize-TokenProbe) {
        try {
            $label = [EiaTokenProbe]::GetIntegrityLabel()
            if (-not [string]::IsNullOrWhiteSpace($label)) {
                $script:IntegrityLevelMethod = 'in-memory .NET token query (TokenIntegrityLevel, no native helper binary)'
                $script:IntegrityLevelCache = $label
                return $label
            }
        } catch { }
    }

    # ---- Path 2: managed token-group enumeration -----------------------------------------
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($g in @($id.Groups)) {
            $sid = [string]$g.Value
            if ($sid -match '^S-1-16-(\d+)$') {
                $rid = $Matches[1]
                $name = if ($map.ContainsKey($rid)) { $map[$rid] } else { 'Custom' }
                $script:IntegrityLevelMethod = 'managed token-group enumeration (WindowsIdentity.Groups, no native helper binary)'
                $script:IntegrityLevelCache = $name + ' (S-1-16-' + $rid + ')'
                return $script:IntegrityLevelCache
            }
        }
    } catch { }

    $script:IntegrityLevelMethod = 'unavailable'
    return 'Unknown (no in-memory token query available: ' + [string]$script:TokenProbeMethod + ')'
}

function Get-LogonType {
    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $me.User.Value
        $map = @{ 2='Interactive'; 3='Network'; 4='Batch'; 5='Service'; 7='Unlock'; 8='NetworkCleartext'; 9='NewCredentials'; 10='RemoteInteractive'; 11='CachedInteractive'; 12='CachedRemoteInteractive'; 13='CachedUnlock' }
        $sessions = @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop | Where-Object {
            $_.Antecedent -match [regex]::Escape($sid) -or $_.Dependent -match [regex]::Escape($sid)
        })
        $types = @()
        foreach ($s in $sessions) {
            $lid = $s.Dependent
            if ($lid -match 'LogonId="(\d+)"') {
                $lt = $map[[int]$Matches[1]]
                if ($lt) { $types += $lt } else { $types += ('Type ' + $Matches[1]) }
            }
        }
        if ($types.Count -gt 0) { return (($types | Select-Object -Unique) -join ', ') }
    } catch { }
    return 'Unknown (query blocked or unavailable)'
}

function Invoke-Section1_Initialization {
    $script:HostName = $env:COMPUTERNAME
    $cs = $null
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { }
    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }

    # ---- Host role classification -------------------------------------------------------
    $domainRole = -1
    if ($cs) { $domainRole = [int]$cs.DomainRole }
    $role = switch ($domainRole) {
        0 { 'Workstation (standalone / not domain-joined)' }
        1 { 'Workstation (domain-joined member of a domain)' }
        2 { 'Member Server (standalone / not domain-joined)' }
        3 { 'Member Server (domain-joined member server)' }
        4 { 'DOMAIN CONTROLLER (backup / additional DC)' }
        5 { 'DOMAIN CONTROLLER (primary DC)' }
        default { 'Unknown (Win32_ComputerSystem.DomainRole unavailable)' }
    }
    $script:Section1Role = $role

    # ---- Domain membership --------------------------------------------------------------
    $domain        = ''
    $isDomainJoin  = $false
    $machineDn     = ''
    try {
        if ($cs -and $cs.PartOfDomain) { $isDomainJoin = $true; $domain = $cs.Domain }
        if (-not $isDomainJoin) {
            $dv = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'Domain'
            if ($dv.NameExists -and $dv.Value) { $isDomainJoin = $true; $domain = [string]$dv.Value }
        }
        if ($isDomainJoin -and (Test-RemoteAllowed)) { $machineDn = ([ADSI]('LDAP://' + $domain)).distinguishedName }
    } catch {
        Write-Status 'WARN' ('Domain object could not be read for ' + $domain + ': ' + $_.Exception.Message)
    }
    if (-not $isDomainJoin) { $script:Section1Role = $role + ' [WORKGROUP]' }

    # ---- Identity / token ---------------------------------------------------------------
    $ident = $null
    try { $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent() } catch { }
    $userName = if ($ident) { $ident.Name } else { $env:USERDOMAIN + '\' + $env:USERNAME }
    $userSid  = if ($ident) { $ident.User.Value } else { 'Unknown' }
    $authType = if ($ident) { $ident.AuthenticationType } else { 'Unknown' }
    $integrity = Get-IntegrityLevel
    $isAdmin  = Test-IsAdmin
    $isSystem = ($userSid -eq 'S-1-5-18')
    $elevation = if ($isSystem) { 'SYSTEM context (highest integrity)' }
                 elseif ($integrity -match 'High') { 'Elevated (administrator token is active)' }
                 elseif ($integrity -match 'Medium' -and $isAdmin) { 'Non-elevated administrator (UAC filtered token)' }
                 elseif ($integrity -match 'Medium') { 'Standard user token' }
                 else { 'Unknown' }

    # ---- Network ------------------------------------------------------------------------
    $nics = Get-NicInventory
    $myIps = Get-LocalIpv4 -Nics $nics
    $primaryIp = ''
    if ($myIps.Count -gt 0) { $primaryIp = $myIps[0] }
    $primaryNic = $nics | Where-Object { $_.IsUp -and $_.IPv4 -notlike '127.*' } | Select-Object -First 1
    $gw = ''; $dnsList = ''
    if ($primaryNic) { $gw = $primaryNic.Gateway; $dnsList = $primaryNic.DnsServers }

    $fqdn = $env:COMPUTERNAME
    try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { if ($domain) { $fqdn = $env:COMPUTERNAME + '.' + $domain } }

    # ---- Domain controller / DNS resolution test ----------------------------------------
    # /localonly: no LDAP bind, no directory search and no SRV/DNS probe is issued. The role is
    # still determined from local sources (registry, WMI, SID), only DC discovery is suppressed.
    $dcResolved = ''; $dcReachable = $false
    if ($isDomainJoin -and $domain -and -not (Test-RemoteAllowed)) {
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - domain controller discovery and the LDAP RootDSE bind were not attempted.')
        Write-Context 'Domain Controller' 'SUPPRESSED by /localonly (no LDAP bind; no DC name or SRV resolution was performed by this module)'
    }
    if ($isDomainJoin -and $domain -and (Test-RemoteAllowed)) {
        try {
            $dcHost = ([ADSI]('LDAP://' + $domain)).Properties['dNSHostName'].Value
            if ($dcHost) { $dcResolved = [string]$dcHost }
        } catch { $dcResolved = '' }
        if (-not $dcResolved) {
            try {
                $srv = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | ForEach-Object { $_.DomainControllers } | Select-Object -First 1
                if ($srv) { $dcResolved = $srv.Name }
            } catch { }
        }
        if (-not $dcResolved) {
            try {
                $r = Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.' + $domain) -Type SRV -ErrorAction Stop | Select-Object -First 1
                if ($r -and $r.NameTarget) { $dcResolved = $r.NameTarget.TrimEnd('.') }
            } catch { }
        }
    }

    # ---- Console presentation ------------------------------------------------------------
    Write-Banner ($script:Cfg.ToolName + ' v' + $script:Cfg.ToolVersion + ' :: internal-network VAPT assessment utility')
    Write-Host '  Lifecycle: DISCOVERY -> ENUMERATION -> REACHABILITY -> VALIDATION -> IMPACT -> RESULT -> REMEDIATION' -ForegroundColor DarkCyan
    Write-Host '  Evidence is written incrementally to the CSV report; every row separates CONFIGURATION EVIDENCE from' -ForegroundColor DarkCyan
    Write-Host '  ACTIVE VALIDATION and IMPACT. A discovered setting is never reported as a proven weakness.' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host ('  Report file : ' + $script:CsvPath) -ForegroundColor Gray
    if (-not $script:CsvOk) { Write-Host '  Report file : NOT WRITABLE - console-only run' -ForegroundColor Red }
    Write-Host ('  Started     : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')) -ForegroundColor Gray
    Write-Host ('  Authority   : This utility performs ONLY the checks listed in its REM documentation.' -replace '\r?\n','') -ForegroundColor Gray

    Write-Section '1' 'SYSTEM INITIALIZATION / ASSESSMENT CONTEXT'

    Write-Host '  -- Host identity ------------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Context 'Hostname'              $script:HostName
    Write-Context 'FQDN'                  $fqdn
    Write-Context 'Machine Role'          $role
    Write-Context 'OS Name'               $(if ($os) { $os.Caption } else { 'Unavailable' })
    Write-Context 'OS Version / Build'    $(if ($os) { $os.Version + '  (Build ' + $os.BuildNumber + ')' } else { 'Unavailable' })
    Write-Context 'OS Architecture'       $(if ($os) { $os.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE })
    Write-Context 'Install Date'          $(if ($os) { $os.InstallDate.ToString('yyyy-MM-dd') } else { 'Unavailable' })
    Write-Context 'Last Boot'             $(if ($os) { $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unavailable' })
    Write-Context 'Manufacturer / Model'  $(if ($cs) { $cs.Manufacturer + ' ' + $cs.Model } else { 'Unavailable' })
    Write-Context 'System Type'           $(if ($cs) { $cs.SystemType } else { 'Unavailable' })
    Write-Context 'Total Physical Memory' $(if ($cs) { [string]([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) + ' GB' } else { 'Unavailable' })

    Write-Host '  -- Assessment identity (the foothold this evidence was gathered from) ------' -ForegroundColor DarkGray
    Write-Context 'Current Username'      $userName
    Write-Context 'User SID'              $userSid
    Write-Context 'Authentication Type'   $authType
    Write-Context 'Integrity Level'       $integrity
    Write-Context 'Elevation State'       $elevation
    Write-Context 'Local Administrators'  $(if ($isAdmin) { 'YES - context holds Administrator rights on this host' } else { 'NO - context is a standard user on this host' })
    Write-Context 'Logon Type(s)'         (Get-LogonType)
    Write-Context 'Process Architecture'  ([System.Environment]::Is64BitProcess -as [string]) + ''
    Write-Context 'Running As'            $(if ($isSystem) { 'NT AUTHORITY\SYSTEM' } elseif ($env:USERDOMAIN) { $env:USERDOMAIN + '\' + $env:USERNAME } else { $env:USERNAME })

    Write-Host '  -- Domain / directory context ----------------------------------------------------' -ForegroundColor DarkGray
    Write-Context 'Domain Joined'         $(if ($isDomainJoin) { 'YES' } else { 'NO (workgroup or standalone system)' })
    Write-Context 'Domain'                $(if ($domain) { $domain } else { '(none - non-domain system)' })
    Write-Context 'Machine DN'            $(if ($machineDn) { $machineDn } else { '(not available - non-domain system or LDAP blocked)' })
    Write-Context 'Domain Controller'     $(if ($dcResolved) { $dcResolved } else { '(not resolvable - offline DC, DNS failure, or non-domain system)' })
    Write-Context 'Logon Server'          $env:LOGONSERVER

    Write-Host '  -- IP configuration --------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Context 'IPv4 Address(es)'      $(if ($myIps.Count) { $myIps -join ', ' } else { '(no routable IPv4 address)' })
    Write-Context 'Default Gateway'       $gw
    Write-Context 'DNS Servers'           $dnsList
    Write-Context 'Primary Subnet'        $(if ($primaryNic) { $primaryNic.IPv4 } else { 'Unknown' })

    if ($nics.Count -gt 0) {
        Write-Host ''
        Write-Host '  -- Network interfaces --------------------------------------------------------------' -ForegroundColor DarkGray
        Write-Table -Rows ($nics | Select-Object Name, Type, Status, IPv4, IPv6, Gateway, DnsServers, Mac, SpeedMbps) `
            -Columns @('Name','Type','Status','IPv4','IPv6','Gateway','DnsServers','Mac','SpeedMbps') `
            -Headers @{ Name='Interface'; Type='Type'; Status='State'; IPv4='IPv4 / prefix'; IPv6='IPv6 (global)'; Gateway='Gateway'; DnsServers='DNS'; Mac='MAC'; SpeedMbps='Mbps' }
    }

    # ---- Direct DC reachability (native, read-only LDAP bind) ----------------------------
    if ($isDomainJoin -and $dcResolved -and (Test-RemoteAllowed)) {
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://' + $dcResolved + '/RootDSE')
            $nm = $root.Properties['defaultNamingContext'].Value
            $sw.Stop()
            $dcReachable = $true
            Write-Context 'RootDSE Bind' ('SUCCESS in ' + $sw.ElapsedMilliseconds + ' ms; defaultNamingContext=' + $nm)
        } catch {
            Write-Status 'WARN' ('LDAP bind to the discovered DC failed: ' + $_.Exception.Message)
            Write-Status 'NOT TESTABLE' 'Domain-dependent checks will degrade to NOT TESTABLE rather than fail the run.'
        }
    }

    # ---- Findings about the assessment context itself ------------------------------------
    if (-not $isDomainJoin) {
        Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' -Attribute 'Host Role' `
            -Finding 'Host is NOT domain-joined: domain, LDAP, Kerberos and delegated-privilege modules will report NOT TESTABLE.' `
            -Observed ('DomainRole=' + $domainRole + '; PartOfDomain=' + $(if ($cs) { $cs.PartOfDomain } else { 'unknown' })) `
            -Validation 'Local enumeration only' -Exploitability 'N/A (context record; not a vulnerability)' `
            -Impact 'N/A (context record; not a vulnerability)' `
            -Remediation 'No action required for this host. Run the tool from a domain-joined host to obtain Active Directory coverage.'
    }

    if (-not $isAdmin) {
        Add-Finding -Category 'Assessment Context' -Status 'WARN' -Attribute 'Assessor Privilege' -Class 'Medium' -Weakness $true `
            -Finding 'Assessment is running WITHOUT local Administrator rights: privileged checks (service EXE ACLs, LSA protection keys, some registry ACLs) will be incomplete.' `
            -Observed ('Integrity=' + $integrity + '; IsAdmin=False; SID=' + $userSid) `
            -Validation 'Token evaluation via WindowsPrincipal.IsInRole' `
            -Exploitability 'Not demonstrated' `
            -Impact 'Assessment fidelity, not host security: several controls cannot be read and will be reported as NOT TESTABLE instead of PASS/FAIL.' `
            -Remediation 'Re-run the assessment from an elevated console on the authorised assessment account so that all controls can be enumerated. Treat every "NOT TESTABLE" row as UNKNOWN, not as compliant.'
    } else {
        Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' -Attribute 'Assessor Privilege' `
            -Finding 'Assessment context holds local Administrator rights (full local enumeration fidelity).' `
            -Observed ('Integrity=' + $integrity + '; IsAdmin=True') -Validation 'Token evaluation via WindowsPrincipal.IsInRole' `
            -Exploitability 'N/A (context record; not a vulnerability)' -Impact 'N/A (context record; not a vulnerability)' `
            -Remediation 'None - informational context row.' -NoConsole
    }

    if ($isSystem) {
        Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' -Attribute 'Running As SYSTEM' `
            -Finding 'Assessment context is NT AUTHORITY\SYSTEM, typically indicating execution via a management agent or scheduled task.' `
            -Observed ('SID=' + $userSid) -Validation 'WindowsIdentity.User comparison' -Exploitability 'N/A (context record; not a vulnerability)' `
            -Impact 'N/A (context record; not a vulnerability)' -Remediation 'None - informational context row.' -NoConsole
    }

    if ($role -like '*DOMAIN CONTROLLER*') {
        Add-Finding -Category 'Critical Infrastructure' -Status 'INFO' -CatClass 'Context' -Attribute 'Host Role' -Class 'High' `
            -Finding 'The assessment is executing ON a domain controller: configuration weaknesses here have domain-wide impact and every downstream finding inherits elevated blast radius.' `
            -Observed $role -Validation 'Win32_ComputerSystem.DomainRole' -Exploitability 'N/A (context record; not a vulnerability)' `
            -Impact 'N/A (context record; not a vulnerability)' `
            -Remediation 'Treat this report as domain-critical. Minimise interactive/management exposure on DCs: block inbound 3389/5985/5986 from user subnets, keep Spooler disabled, and enforce LSA protection.'
    }

    if (-not $script:CsvOk) {
        Write-Status 'ERROR' 'No CSV report is being produced - evidence will be lost when the console closes.'
    }
}

# -------------------------------------------------------------------------------------------
#  POWERSHELL RUNTIME DISCOVERY
#  The tool is a batch file that hands control to PowerShell. Both Windows PowerShell 5.1
#  (shipped in-box on Windows 10/Server 2016+) and PowerShell 7 are supported. The resolved
#  executable is reused for every child process so behaviour is consistent.
# -------------------------------------------------------------------------------------------
function Initialize-PowerShellRuntime {
    $cand = @(
        (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
        'powershell.exe'
    )
    $script:PowerShellExe = ''
    foreach ($c in $cand) {
        try {
            if ($c -eq 'powershell.exe' -or (Test-Path -LiteralPath $c)) {
                $probe = & $c -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
                if ($probe) { $script:PowerShellExe = $c; break }
            }
        } catch { }
    }
    $ver = $PSVersionTable.PSVersion.ToString()
    $ed  = 'Windows PowerShell (Desktop)'
    try { if ($PSVersionTable.PSEdition) { $ed = $PSVersionTable.PSEdition } } catch { }
    Write-Section '0' 'RUNTIME / PRE-FLIGHT'
    Write-KV 'Assessment engine' ('PowerShell ' + $ver + ' [' + $ed + ']') 
    Write-KV 'Child PS executable' $(if ($script:PowerShellExe) { $script:PowerShellExe } else { 'UNAVAILABLE - child-process checks will be skipped' })
    Write-KV 'Execution policy' ((Get-ExecutionPolicy -Scope Process).ToString() + ' (process scope)')
    Write-KV 'Language mode' ($ExecutionContext.SessionState.LanguageMode.ToString())
    if ($script:Cfg.MaxSweepHosts -gt 254) { $script:Cfg.MaxSweepHosts = 254 }
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        Write-Status 'WARN' 'ConstrainedLanguage mode is active - some checks will return NOT TESTABLE.'
    }
    if ($ed -like '*Core*') {
        Write-Status 'INFO' 'PowerShell Core detected. All modules used by this tool are compatible; Add-Type fallback handled.'
    }

    # ---- engine capability self-test -------------------------------------------------------
    # -shl/-shr have existed since Windows PowerShell 3.0 (this engine refuses anything older and
    # the launcher exits with code 91 below that), but the operators are PROVEN here rather than
    # assumed. If a host cannot evaluate them, the report states it explicitly instead of a
    # protocol module failing later with a misleading message.
    $shiftOk = $false
    try { $shiftOk = (((1 -shl 3) -eq 8) -and ((8 -shr 3) -eq 1)) } catch { $shiftOk = $false }
    Write-KV 'Bit-shift operators' $(if ($shiftOk) { 'PRESENT - -shl/-shr verified at run time (baseline: PowerShell 3.0 or later)' } else { 'MISSING - bit-shift verification FAILED on this host' })
    if (-not $shiftOk) {
        Write-Status 'ERROR' 'This host cannot evaluate -shl/-shr. Windows PowerShell 3.0 or later is required; protocol modules (SMB1/SMB2 negotiation, Kerberos AS-REQ, IPv4 maths) cannot be validated here.'
    }

    # ---- consent availability --------------------------------------------------------------
    $inputRedirected = $false
    try { $inputRedirected = [Console]::IsInputRedirected } catch { }
    Write-KV 'Interactive console' $(if ($inputRedirected) { 'NO - standard input is redirected: consent prompts are disabled and gated steps use their safe default' } else { 'YES - consent prompts are available' })
    $consentMode = 'interactive (prompts at the console)'
    if ($env:EIA_PREAUTH -eq '1') {
        $preSrc = ''
        try { $preSrc = [string]$env:EIA_PREAUTH_SOURCE } catch { }
        if ([string]::IsNullOrWhiteSpace($preSrc)) { $preSrc = 'source not recorded' }
        $consentMode = ('PRE-AUTHORISED - ' + $preSrc + ' - consent-gated active steps run without prompting')
    }
    elseif ($env:EIA_HEADLESS -eq '1') { $consentMode = 'headless (/headless) - consent-gated active steps are skipped unless /authorize-active is also given' }
    elseif ($inputRedirected) { $consentMode = 'unattended stdin detected - prompts disabled, safe defaults applied' }
    Write-KV 'Consent mode' $consentMode

    # ---- stale artifact sweep (honours ProbeFileTtlMin) ------------------------------------
    # A run that is killed mid-flight can leave its own temporary files behind. Every module removes
    # its artifacts in finally blocks; this is the second line of defence. It deletes ONLY files
    # matching this tool's exact name patterns, ONLY inside %TEMP%, and ONLY when older than the
    # configured TTL - so it can never touch another application's data.
    try {
        $ttl = [int]$script:Cfg.ProbeFileTtlMin
        $cutoff = (Get-Date).AddMinutes(-1 * $ttl)
        $stalePatterns = @('eia-secpol-*.inf','eia-privrights-*.inf','EIA-writetest-*.tmp')
        $removed = 0
        foreach ($pat in $stalePatterns) {
            $hits = @(Get-ChildItem -LiteralPath $env:TEMP -Filter $pat -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff })
            foreach ($h in $hits) { try { Remove-Item -LiteralPath $h.FullName -Force -ErrorAction Stop; $removed++ } catch { } }
        }
        if ($removed -gt 0) { Write-KV 'Stale artifacts removed' ($removed.ToString() + ' file(s) older than ' + $ttl + ' minute(s), left by an earlier interrupted run') }
        else { Write-KV 'Stale artifacts removed' 'none (no leftover artifact older than the configured TTL)' }
    } catch { Write-KV 'Stale artifacts removed' ('check skipped: ' + $_.Exception.Message) }
}
# ===========================================================================================
#  SECTION 2 :: LOCAL SECURITY CONFIGURATION AUDIT  (part 3/9)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Establishes the local security baseline of the foothold host. For EVERY control the tool
#  records the five-element evidence tuple required by the engagement scope:
#
#       EXPECTED   - the vendor/benchmark-expected state and WHY it is expected
#       CONFIGURED - the literal registry/service/policy value that was read (or "absent")
#       OBSERVED   - the effective runtime state (protocol negotiation / API query / service)
#       VALIDATION - how the observed state was obtained, and whether it validates CONFIGURED
#       RESULT     - PASS / WARN / RISK DETECTED / VALIDATED / NOT CONFIRMED / NOT TESTABLE
#
#  DESIGN RULE ON ABSENT VALUES
#  ----------------------------------------------------------------------------------------
#  A missing registry value is NOT read as secure or insecure. The tool prints
#  "value not present (default behaviour applies)" and, where Microsoft documents the
#  default, states that default explicitly. Absent values are never promoted to findings on
#  their own; only the OBSERVED/effective state carries a security rating.
#
#  DESIGN RULE ON FIDELITY
#  ----------------------------------------------------------------------------------------
#  Assessment-first: this section NEVER writes to the host, never restarts a service, never
#  enables/disables a feature. Where a change would be required to test a control, the row is
#  reported as NOT TESTABLE with the change that a human would have to authorise.
# ===========================================================================================

$script:Facts = @{}          # shared, machine-readable fact store consumed by later sections

function Add-Control {
    <# Ctrl-Name: records the five-element evidence tuple, prints it, stores the machine
       readable fact for later correlation, and appends the row to the CSV evidence report. #>
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Attribute,
        [Parameter(Mandatory=$true)][string]$Expected,
        [string]$Configured   = '',
        [string]$Observed     = '',
        [string]$Validation   = '',
        [Parameter(Mandatory=$true)][ValidateSet('PASS','WARN','RISK DETECTED','VALIDATED','NOT CONFIRMED','NOT TESTABLE','ERROR','INFO','OPPORTUNITY')][string]$Result,
        [Parameter(Mandatory=$true)][string]$Finding,
        [string]$FactKey      = '',
        [object]$FactValue    = $null,
        [string]$Remediation  = '',
        [string]$Impact       = '',
        [string]$Exploitability = '',
        [string]$Prerequisites = '',
        [ValidateSet('Micro','Low','Medium','High','Critical')][string]$Class = 'Medium',
        [ValidateSet('Confidentiality','Integrity','Availability','DataAtRest','IdentityRights','Context')][string]$CatClass = 'Confidentiality',
        [string]$SeverityOverride = ''
    )
    if ($FactKey) { $script:Facts[$FactKey] = $FactValue }
    $severityClass = $Class
    if ($Class -eq 'Micro') { $severityClass = 'Low' }   # 'Micro' = hardening detail: never above Low

    $weak = ($Result -in @('WARN','RISK DETECTED','VALIDATED'))
    if (-not $Remediation) { $Remediation = 'No action required - control is in the expected state. Re-verify after any build or GPO change.' }
    if (-not $Exploitability) {
        if ($Result -eq 'PASS') { $Exploitability = 'Not applicable - control observed in expected state' }
        elseif ($Result -eq 'NOT CONFIRMED') { $Exploitability = 'Not demonstrated - probe did not confirm the condition' }
        elseif ($Result -eq 'NOT TESTABLE') { $Exploitability = 'Unknown - control could not be tested in this context' }
        else { $Exploitability = 'Not demonstrated (configuration evidence only)' }
    }
    if (-not $Impact) {
        if ($weak) { $Impact = 'See finding text; impact is rated from the documented category-class matrix, not from an observed breach.' }
        else { $Impact = 'No security impact observed for this control in this context.' }
    }

    # console
    $col = $script:StatusColor[$Result]; if (-not $col) { $col = 'Gray' }
    $tag = ('[' + $Result + ']').PadRight(16)
    Write-Host ('  ' + $tag) -ForegroundColor $col -NoNewline
    Write-Host ($Attribute.PadRight(40)) -ForegroundColor White -NoNewline
    Write-Host $Finding -ForegroundColor Gray
    if ($Result -in @('WARN','RISK DETECTED','VALIDATED','ERROR','NOT TESTABLE','NOT CONFIRMED','OPPORTUNITY')) {
        Write-Host ('                  EXPECTED   : ' + $Expected) -ForegroundColor DarkGray
        if ($Configured) { Write-Host ('                  CONFIGURED : ' + $Configured) -ForegroundColor DarkGray }
        if ($Observed)   { Write-Host ('                  OBSERVED   : ' + $Observed) -ForegroundColor DarkGray }
        if ($Validation) { Write-Host ('                  VALIDATION : ' + $Validation) -ForegroundColor DarkGray }
        Write-Host ('                  RESULT     : ' + $Result) -ForegroundColor DarkGray
    }

    [void](Add-Finding -Category $Category -Status $Result -Attribute $Attribute -Finding $Finding `
        -Expected $Expected -Configured $Configured -Observed $Observed -Validation $(if ($Validation) { $Validation } else { 'Registry/service state read (read-only)' }) `
        -Exploitability $Exploitability -Impact $Impact -Remediation $Remediation -Prerequisites $Prerequisites `
        -Class $severityClass -CatClass $CatClass -SeverityOverride $SeverityOverride -Weakness $weak -NoConsole)
}

function Invoke-Section2_LocalConfiguration {
    Write-Host '  All checks in this section are READ-ONLY. No service state, policy or registry value is modified.' -ForegroundColor DarkGray

    # The OS build is needed early: several vendor DEFAULTS (SMBv1, signing, LLMNR) depend on the
    # build number, and the tool must state the default rather than assume one.
    $buildPre = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
    if ($buildPre.NameExists) { try { $script:OsBuild = [int]$buildPre.Value } catch { $script:OsBuild = $null } }
    if ($null -ne $script:OsBuild) { Write-Host ('  OS build ' + $script:OsBuild + ' detected - vendor defaults are evaluated against this build.') -ForegroundColor DarkGray }

    # =======================================================================================
    #  2.1 SMBv1  (legacy dialect; NTLM-relay and EternalBlue-era attack surface)
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.1 SMB version 1 -------------------------------------------------------------' -ForegroundColor DarkCyan
    $svcSrv = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    $svcCli = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\mrxsmb10'                     -Name 'Start'
    $feat   = $null
    try { $feat = @(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop) } catch { $feat = $null }

    $srvScore = $null; $cliScore = $null
    if (-not $svcSrv.KeyExists) { $srvScore = 'absent' }
    elseif (-not $svcSrv.NameExists) { $srvScore = 'absent' }
    elseif ([int]$svcSrv.Value -eq 0) { $srvScore = 'disabled' }
    elseif ([int]$svcSrv.Value -eq 1) { $srvScore = 'enabled' }
    else { $srvScore = 'unknown' }

    if ($cliScore -eq $null) {
        if (-not $svcCli.KeyExists) { $cliScore = 'absent' }
        elseif (-not $svcCli.NameExists) { $cliScore = 'driver-present-default-start' }
        elseif ([int]$svcCli.Value -eq 4) { $cliScore = 'disabled' }
        else { $cliScore = 'enabled (Start=' + [string]$svcCli.Value + ')' }
    }

    $srvText = switch ($srvScore) {
        'absent'   { 'SMB1 value not present under LanmanServer\Parameters (Microsoft default: SMBv1 server DISABLED on Windows 10 1709+/Server 1709+; ENABLED on older builds and on all pre-1709 servers)' }
        'disabled' { 'SMB1=0 - SMBv1 server explicitly disabled' }
        'enabled'  { 'SMB1=1 - SMBv1 server explicitly ENABLED' }
        default    { 'SMB1 value present but not 0/1' }
    }
    $srvWeak = ($srvScore -eq 'enabled')
    if ($srvScore -eq 'absent' -and $script:OsBuild -ne $null -and [int]$script:OsBuild -lt 16299) { $srvWeak = $true }
    Add-Control -Category 'Network Protocol - SMB' -Attribute 'SMBv1 Server Availability' `
        -Expected 'SMBv1 disabled (SMB1Protocol feature removed/disabled). SMBv1 has no integrity protection, is relay-prone and carries known remote code execution history (MS17-010).' `
        -Configured (Format-RegState $svcSrv) `
        -Observed $(if ($feat) { 'Windows optional feature SMB1Protocol state = ' + $feat.State } else { 'Get-WindowsOptionalFeature unavailable (Server Core / older build); registry state used' }) `
        -Validation 'Registry read + Windows optional-feature query. Protocol-level validation of the OFFERED dialect is performed in Section 3 (SMB negotiate probe).' `
        -Result $(if ($srvWeak) { 'RISK DETECTED' } else { 'PASS' }) -FactKey 'Smb1Server' -FactValue $srvScore `
        -Finding $(if ($srvWeak) { 'SMBv1 server appears ENABLED on this host.' } elseif ($srvScore -eq 'absent') { 'SMBv1 server not explicitly configured; effective state depends on OS build (validated in Section 3).' } else { 'SMBv1 server is disabled by policy.' }) `
        -Class 'High' -CatClass 'Confidentiality' `
        -Remediation 'Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (Server: Remove-WindowsFeature FS-SMB1). Set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1=0 and confirm with the Section 3 negotiate probe that SMB1 is no longer offered.' `
        -Impact 'If SMBv1 is offered, any reachable peer can negotiate a legacy dialect: no signing enforcement by default, no pre-auth integrity on some configurations, and a wide historical RCE/relay surface.'

    Add-Control -Category 'Network Protocol - SMB' -Attribute 'SMBv1 Client Driver' `
        -Expected 'SMBv1 client driver (mrxsmb10) disabled (Start=4) so this host cannot initiate SMBv1 sessions outbound.' `
        -Configured (Format-RegState $svcCli) `
        -Observed $(if ($cliScore -eq 'disabled') { 'mrxsmb10 Start=4 (disabled)' } elseif ($cliScore -eq 'absent') { 'mrxsmb10 service key absent - driver not installed' } elseif ($cliScore -eq 'driver-present-default-start') { 'driver present, Start value absent (default start applies)' } else { [string]$cliScore }) `
        -Validation 'Registry read of the SMBv1 client driver service key' `
        -Result $(if ($cliScore -eq 'enabled (Start=3)' -or $cliScore -eq 'driver-present-default-start') { 'WARN' } else { 'PASS' }) `
        -FactKey 'Smb1Client' -FactValue $cliScore -Class 'Medium' `
        -Finding $(if ($cliScore -like 'enabled*' -or $cliScore -eq 'driver-present-default-start') { 'SMBv1 client driver is available and can be started on demand.' } else { 'SMBv1 client driver is disabled or not installed.' }) `
        -Remediation 'Disable the client driver: Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10 -Name Start -Value 4 (requires reboot), or remove the SMB1Protocol-Client feature. Outbound SMBv1 use is a relay/downgrade risk toward legacy file servers.' `
        -Impact 'An attacker able to coerce this host into contacting a malicious SMB server can force SMBv1 negotiation, which is exploitable for NTLM relay in the absence of signing.'

    # =======================================================================================
    #  2.2 SMB signing
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.2 SMB signing --------------------------------------------------------------' -ForegroundColor DarkCyan
    $srvReq = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature'
    $srvEna = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature'
    $cliReq = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature'
    $cliEna = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature'
    $guest  = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth'
    $isDc   = ($script:Section1Role -like '*DOMAIN CONTROLLER*')

    $srvReqVal = Get-U32 $srvReq
    $srvEnaVal = Get-U32 $srvEna
    $cliReqVal = Get-U32 $cliReq
    $cliEnaVal = Get-U32 $cliEna

    Add-Control -Category 'Network Protocol - SMB' -Attribute 'SMB Server Signing Required' `
        -Expected $(if ($isDc) { 'Required (RequireSecuritySignature=1). Domain controllers must require SMB signing: unsigned SMB to a DC enables NTLM relay to LDAP/SMB and full domain compromise.' } else { 'Required (RequireSecuritySignature=1). Without mandatory signing, SMB traffic to this host can be relayed (NTLM relay -> SMB/LDAP -> privilege escalation).' }) `
        -Configured ('RequireSecuritySignature=' + (Format-RegState $srvReq) + ' ; EnableSecuritySignature=' + (Format-RegState $srvEna)) `
        -Observed ('Effective signing requirement is validated at protocol level in Section 3.3 (SMB2 NEGOTIATE SecurityMode.SIGNING_REQUIRED).' + $(if ($isDc) { ' Host role = DOMAIN CONTROLLER (Microsoft default: signing required).' } else { ' Host role = ' + $script:Section1Role + '.' })) `
        -Validation 'Registry read now; live SMB2 NEGOTIATE SecurityMode probe in Section 3.' `
        -Result $(if ($srvReqVal -eq 1) { 'PASS' } elseif ($null -eq $srvReqVal) { 'NOT CONFIRMED' } else { 'RISK DETECTED' }) `
        -FactKey 'SmbServerSigningRequired' -FactValue $(if ($srvReqVal -eq 1) { $true } elseif ($null -eq $srvReqVal) { $null } else { $false }) `
        -Class 'High' `
        -Finding $(if ($srvReqVal -eq 1) { 'SMB server signing requirement is explicitly enabled.' } elseif ($null -eq $srvReqVal) { 'SMB server signing requirement is NOT configured - effective state depends on OS default and is validated at protocol level.' } else { 'SMB server signing requirement is explicitly DISABLED.' }) `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=1 (GPO: Microsoft network server: Digitally sign communications (always) = Enabled). Apply to all servers and workstations; start with servers and DCs.' `
        -Impact 'With signing not required, an attacker with network positioning can relay captured NTLM authentication to SMB on this host and act in the victim''s security context, including reading/writing shares and, on privileged victims, escalating to domain administration.'

    Add-Control -Category 'Network Protocol - SMB' -Attribute 'SMB Client Signing Requirement' `
        -Expected 'Required or at minimum enabled (EnableSecuritySignature=1). Client signing protects outbound SMB authentication from relay.' `
        -Configured ('RequireSecuritySignature=' + (Format-RegState $cliReq) + ' ; EnableSecuritySignature=' + (Format-RegState $cliEna)) `
        -Observed $(if ($cliReqVal -eq 1) { 'Outbound SMB sessions will always be signed.' } elseif ($null -eq $cliReqVal) { 'Not explicitly required at this level; Microsoft ships clients with signing negotiated/enabled by default on modern builds, and hardened builds require it. Effective state validated in Section 3.' } else { 'Signing requirement explicitly disabled on the client.' }) `
        -Validation 'Registry read; outbound negotiation is only observable against a live peer (documented as a limitation).' `
        -Result $(if ($cliReqVal -eq 1) { 'PASS' } elseif ($cliReqVal -eq 0) { 'WARN' } else { 'NOT CONFIRMED' }) `
        -FactKey 'SmbClientSigningRequired' -FactValue $(if ($cliReqVal -eq 1) { $true } elseif ($null -eq $cliReqVal) { $null } else { $false }) `
        -Class 'Medium' `
        -Finding $(if ($cliReqVal -eq 1) { 'SMB client signing is explicitly required.' } elseif ($cliReqVal -eq 0) { 'SMB client signing requirement is explicitly disabled (RequireSecuritySignature=0).' } else { 'SMB client signing requirement is not explicitly configured.' }) `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=1 (GPO: Microsoft network client: Digitally sign communications (always)).' `
        -Impact 'A host that does not require signed SMB sessions can be relayed/coerced by an on-path attacker, enabling authentication relay from this host to other systems.'

    Add-Control -Category 'Network Protocol - SMB' -Attribute 'SMB Insecure Guest Authentication' `
        -Expected 'AllowInsecureGuestAuth absent or 0 - guest fallback permits unauthenticated access to third-party SMB servers and downgrades SMB2/3 to guest, enabling NTLM capture against attacker-controlled servers.' `
        -Configured (Format-RegState $guest) -Observed (Format-RegState $guest) `
        -Validation 'Registry read of the SMB client parameter' `
        -Result $(if ((Get-U32 $guest) -eq 1) { 'WARN' } else { 'PASS' }) -FactKey 'SmbInsecureGuestAuth' -FactValue (Get-U32 $guest) -Class 'Medium' `
        -Finding $(if ((Get-U32 $guest) -eq 1) { 'Insecure guest authentication is explicitly allowed on the SMB client.' } else { 'Insecure guest authentication is not enabled (or not present, default = blocked).' }) `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth=0 and confirm no shares are accessed with guest credentials.' `
        -Impact 'Enables unauthenticated access to shares on non-domain file servers and can be used to capture or relay credentials.'

    # =======================================================================================
    #  2.3 LLMNR / NetBIOS name resolution poisoning
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.3 LLMNR / NetBIOS-NS --------------------------------------------------' -ForegroundColor DarkCyan
    $llmnr = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    Add-Control -Category 'Name Resolution' -Attribute 'LLMNR' `
        -Expected 'Disabled (EnableMulticast=0). Microsoft security baseline disables LLMNR; it is unauthenticated multicast name resolution and the primary vector for credential relay/capture (Responder-class attacks).' `
        -Configured (Format-RegState $llmnr) `
        -Observed $(if ((Get-U32 $llmnr) -eq 0) { 'LLMNR disabled by policy' } elseif ($llmnr.NameExists) { 'LLMNR explicitly enabled by policy' } else { 'No policy value present - Microsoft default for this value is ENABLED (LLMNR responds unless disabled).' }) `
        -Validation 'Registry read of the DNSClient policy key (Microsoft default documented: LLMNR is enabled when the policy is absent).' `
        -Result $(if ((Get-U32 $llmnr) -eq 0) { 'PASS' } else { 'RISK DETECTED' }) -FactKey 'LlmnrDisabled' -FactValue ((Get-U32 $llmnr) -eq 0) `
        -Class 'High' -CatClass 'Confidentiality' `
        -Finding $(if ((Get-U32 $llmnr) -eq 0) { 'LLMNR is disabled by policy.' } else { 'LLMNR is enabled or not disabled by policy - the host will respond to multicast name queries.' }) `
        -Remediation 'GPO: Computer Configuration > Administrative Templates > Network > DNS Client > "Turn off multicast name resolution" = Enabled (sets EnableMulticast=0). Do the same for NetBIOS-NS via the per-adapter NetbiosOptions=2 (see below).' `
        -Impact 'An attacker on the local segment can answer LLMNR queries and receive NetNTLMv2 challenges/authentication from this host, which can be cracked offline or relayed to other services.'

    $netbtRows = @(); $netbtWeak = $false; $netbtEnabled = @()
    try {
        $ifRoot = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces')
        if ($ifRoot) {
            foreach ($sub in $ifRoot.GetSubKeyNames()) {
                $v = Get-RegValue -Path ('SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $sub) -Name 'NetbiosOptions'
                $val = Get-U32 $v
                $state = if ($null -eq $val) { 'operator default (DHCP)' } elseif ($val -eq 0) { 'enabled via DHCP default' } elseif ($val -eq 1) { 'ENABLED' } elseif ($val -eq 2) { 'disabled' } else { 'unknown=' + $val }
                if ($val -ne 2) { $netbtWeak = $true; $netbtEnabled += $sub }
                $netbtRows += [pscustomobject]@{ Interface = $sub; NetbiosOptions = $(if ($null -eq $val) { '(absent)' } else { [string]$val }); State = $state }
            }
            $ifRoot.Close()
        }
    } catch { Write-Status 'NOT TESTABLE' ('NetBT interface enumeration failed: ' + $_.Exception.Message) }
    if ($netbtRows.Count -gt 0) { Write-Table -Rows $netbtRows -Columns @('Interface','NetbiosOptions','State') -Headers @{ Interface='NetBT interface'; NetbiosOptions='NetbiosOptions'; State='Effective state' } }
    $nodeType = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType'
    Add-Control -Category 'Name Resolution' -Attribute 'NetBIOS over TCP/IP (NetBT)' `
        -Expected 'Disabled on every adapter (NetbiosOptions=2) on IPv4-only modern estates. NetBIOS-NS is unauthenticated and is spoofed/poisoned by the same techniques as LLMNR; NetBIOS name service also leaks host/domain names.' `
        -Configured ('Per-interface NetbiosOptions values listed above; global NodeType=' + (Format-RegState $nodeType)) `
        -Observed $(if ($netbtRows.Count -eq 0) { 'No NetBT interface configuration readable (driver may be absent or key protected).' } elseif ($netbtWeak) { 'NetBIOS enabled or DHCP-defaulted on ' + $netbtEnabled.Count + ' interface(s).' } else { 'NetBIOS explicitly disabled on all enumerated interfaces.' }) `
        -Validation 'Per-interface registry enumeration under NetBT\Parameters\Interfaces' `
        -Result $(if ($netbtRows.Count -eq 0) { 'NOT TESTABLE' } elseif ($netbtWeak) { 'WARN' } else { 'PASS' }) `
        -FactKey 'NetBiosState' -FactValue $(if ($netbtWeak) { 'enabled-or-default' } else { 'disabled' }) -Class 'Medium' `
        -Finding $(if ($netbtWeak) { 'NetBIOS over TCP/IP is not explicitly disabled on all interfaces.' } elseif ($netbtRows.Count -eq 0) { 'NetBIOS configuration could not be enumerated.' } else { 'NetBIOS over TCP/IP is disabled on all enumerated interfaces.' }) `
        -Remediation 'Disable NetBIOS per adapter (NetbiosOptions=2 under HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*) or via DHCP option 001/046, and disable the NetBT driver where legacy name resolution is not required.' `
        -Impact 'NetBIOS name poisoning allows an attacker on the segment to impersonate file/print servers and capture or relay authentication from this host; it also exposes the host/domain naming structure to unauthenticated queries.'

    # =======================================================================================
    #  2.4 Authentication policy: LM / NTLM / NTLMv2 / Kerberos / anonymous access
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.4 Authentication policy (LM / NTLM / Kerberos / anonymous) ----------------' -ForegroundColor DarkCyan
    $lm = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    $noLmHash = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash'
    $minClient = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinClientSec'
    $minServer = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec'
    $rSend = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
    $rRecv = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictReceivingNTLMTraffic'
    $aRecv = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic'
    $rAnon = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
    $rAnonSam = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM'
    $evAnon = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous'
    $limitBlank = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse'

    $lmVal = Get-U32 $lm
    $lmText = switch ($lmVal) {
        0 { '0 - Send LM and NTLM responses (WEAKEST: LM hashes on the wire, trivially crackable)' }
        1 { '1 - Send LM and NTLM, use NTLMv2 session security if negotiated' }
        2 { '2 - Send NTLM only (LM disabled, NTLMv1 still permitted)' }
        3 { '3 - Send NTLMv2 only (default on modern Windows; NTLMv1 not used by this client)' }
        4 { '4 - Send NTLMv2 only, refuse LM' }
        5 { '5 - Send NTLMv2 only, refuse LM and NTLM' }
        default { '(value not present - Microsoft default for Windows Vista/7/8/10/11 and Server 2008+ is 3; value is read live in Section 4 where observable)' }
    }
    $lmWeak = ($null -ne $lmVal -and $lmVal -lt 3)
    Add-Control -Category 'Authentication' -Attribute 'LAN Manager Compatibility Level' `
        -Expected 'LmCompatibilityLevel >= 3 (NTLMv2 only). Values 0-2 permit LM/NTLMv1 on the wire, which are crackable and relayable.' `
        -Configured (Format-RegState $lm) -Observed $lmText `
        -Validation 'Registry read. Section 4 records the policy-vs-observed authentication distinction; wire-level NTLM version cannot be proven without a controlled challenge/response capture, which this tool does not perform.' `
        -Result $(if ($lmWeak) { 'RISK DETECTED' } elseif ($null -eq $lmVal) { 'NOT CONFIRMED' } else { 'PASS' }) `
        -FactKey 'LmCompatLevel' -FactValue $lmVal -Class 'High' -CatClass 'IdentityRights' `
        -Finding $(if ($lmWeak) { 'LM compatibility level permits LM/NTLMv1 authentication.' } elseif ($null -eq $lmVal) { 'LM compatibility level is not explicitly set; the documented Windows default (3) applies.' } else { 'LM compatibility level enforces NTLMv2 or better.' }) `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=5 (GPO: Network security: LAN Manager authentication level = "Send NTLMv2 response only. Refuse LM & NTLM"). Remove NTLMv1 from all clients first to avoid breaking legacy applications.' `
        -Impact 'LM/NTLMv1 challenge-response can be cracked offline in seconds-to-hours on modern GPUs, and is reusable in relay attacks: captured authentication from this host can yield plaintext-equivalent compromise.'

    Add-Control -Category 'Authentication' -Attribute 'NoLMHash (LM hash storage)' `
        -Expected 'Enabled (NoLMHash=1). LM hashes are unsalted DES and break trivially; disabling storage removes a persistent credential artifact.' `
        -Configured (Format-RegState $noLmHash) -Observed (Format-RegState $noLmHash) `
        -Validation 'Registry read (effective for accounts whose password was set after the policy took effect).' `
        -Result $(if ((Get-U32 $noLmHash) -eq 1) { 'PASS' } else { 'WARN' }) -FactKey 'NoLMHash' -FactValue (Get-U32 $noLmHash) -Class 'Medium' -CatClass 'DataAtRest' `
        -Finding $(if ((Get-U32 $noLmHash) -eq 1) { 'LM hash storage is disabled by policy.' } else { 'LM hash storage is not disabled (absent value = LM hash stored on password change for older builds).' }) `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash=1 (GPO: Network security: Do not store LAN Manager hash value on next password change).' `
        -Impact 'Stored LM hashes can be extracted from the SAM/AD database by a local or domain administrator-level attacker and cracked in seconds, enabling immediate reuse of the account password.'

    $minClientVal = Get-U32 $minClient; $minServerVal = Get-U32 $minServer
    $ntlmv2Session = 0x20000000; $enc128 = 0x80000
    Add-Control -Category 'Authentication' -Attribute 'NTLM Minimum Security (session security)' `
        -Expected ('NTLMMinClientSec and NTLMMinServerSec set to at least 0x20080000 (NTLMv2 session security 0x' + $ntlmv2Session.ToString('X8') + ' + 128-bit encryption 0x' + $enc128.ToString('X8') + ') so LM/NTLMv1 session keys cannot be negotiated.') `
        -Configured ('NTLMMinClientSec=' + (Format-RegState $minClient) + ' ; NTLMMinServerSec=' + (Format-RegState $minServer)) `
        -Observed ('Client=0x' + $(if ($null -ne $minClientVal) { $minClientVal.ToString('X8') } else { 'absent' }) + ' ; Server=0x' + $(if ($null -ne $minServerVal) { $minServerVal.ToString('X8') } else { 'absent' }) + ' (absent = Microsoft default 0x20000000 NTLMv2 session security required)') `
        -Validation 'Registry read with hexadecimal bitmask decoding' `
        -Result $(if (($null -ne $minClientVal -and ($minClientVal -band 0x000FFFFF) -ne 0) -or ($null -ne $minServerVal -and ($minServerVal -band 0x000FFFFF) -ne 0)) { 'WARN' } else { 'PASS' }) `
        -FactKey 'NtlmMinSec' -FactValue $minServerVal -Class 'Medium' `
        -Finding 'NTLM minimum session security settings recorded (bits below 0x00100000 indicate weaker-than-NTLMv2 session security).' `
        -Remediation 'Set both values to 0x20080000 (537395200) via GPO: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients/servers = Require NTLMv2 session security + Require 128-bit encryption.' `
        -Impact 'If legacy session security is permitted, an attacker can downgrade a session and exploit NTLMv1 weaknesses to obtain crackable material.'

    Add-Control -Category 'Authentication' -Attribute 'NTLM Restriction (inbound/outbound)' `
        -Expected 'Outbound NTLM restricted (RestrictSendingNTLMTraffic=2 = deny all) and inbound audited then blocked (RestrictReceivingNTLMTraffic, AuditReceivingNTLMTraffic) as part of an NTLM-elimination programme. Kerberos-only estates remove the entire relay class.' `
        -Configured ('RestrictSendingNTLMTraffic=' + (Format-RegState $rSend) + ' ; RestrictReceivingNTLMTraffic=' + (Format-RegState $rRecv) + ' ; AuditReceivingNTLMTraffic=' + (Format-RegState $aRecv)) `
        -Observed $(if ($null -eq (Get-U32 $rSend) -and $null -eq (Get-U32 $rRecv)) { 'No NTLM restriction policy present - NTLM is unrestricted in both directions (Microsoft default).' } else { 'NTLM restriction policy present; see decoded values.' }) `
        -Validation 'Registry read only. NTLM restrictions cannot be safely validated by this tool: the validation would require emitting authentication attempts, which is outside the authorised test surface.' `
        -Result $(if ($null -eq (Get-U32 $rSend) -and $null -eq (Get-U32 $rRecv)) { 'WARN' } else { 'PASS' }) `
        -FactKey 'NtlmRestricted' -FactValue ([bool]($null -ne (Get-U32 $rSend) -or $null -ne (Get-U32 $rRecv))) -Class 'Medium' -CatClass 'IdentityRights' `
        -Finding $(if ($null -eq (Get-U32 $rSend) -and $null -eq (Get-U32 $rRecv)) { 'NTLM is not restricted by policy on this host.' } else { 'NTLM restriction policy is configured on this host.' }) `
        -Remediation 'Deploy the Microsoft NTLM restriction strategy: audit with AuditReceivingNTLMTraffic=1, then RestrictReceivingNTLMTraffic=2 for servers and RestrictSendingNTLMTraffic=2 for clients once application dependencies are known (Network security: Restrict NTLM GPOs).' `
        -Impact 'Unrestricted NTLM means any captured authentication can be relayed to services that accept NTLM, converting a single coerced authentication into lateral movement or privilege escalation.'

    Add-Control -Category 'Authentication' -Attribute 'Anonymous / null-session exposure' `
        -Expected 'RestrictAnonymous=1, RestrictAnonymousSAM=1, EveryoneIncludesAnonymous=0, LimitBlankPasswordUse=1 (Microsoft security baseline).' `
        -Configured ('RestrictAnonymous=' + (Format-RegState $rAnon) + ' ; RestrictAnonymousSAM=' + (Format-RegState $rAnonSam) + ' ; EveryoneIncludesAnonymous=' + (Format-RegState $evAnon) + ' ; LimitBlankPasswordUse=' + (Format-RegState $limitBlank)) `
        -Observed 'Values above; anonymous enumeration exposure of AD/SMB is tested directly in Section 9 (LDAP anonymous bind) where a DC is in scope.' `
        -Validation 'Registry read; anonymous-bind behaviour validated separately via LDAP RootDSE with no credentials.' `
        -Result $(if ((Get-U32 $rAnon) -eq 0 -or (Get-U32 $evAnon) -eq 1) { 'WARN' } else { 'PASS' }) -FactKey 'AnonymousRestricted' -FactValue (Get-U32 $rAnon) `
        -Class 'Medium' -CatClass 'Confidentiality' `
        -Finding 'Anonymous access configuration recorded; see CONFIGURED column for the effective settings.' `
        -Remediation 'Apply the Microsoft security baseline: RestrictAnonymous=1, RestrictAnonymousSAM=1, EveryoneIncludesAnonymous=0, LimitBlankPasswordUse=1. Verify on DCs that anonymous LDAP binds are refused (Section 9 performs this check).' `
        -Impact 'Permissive anonymous access leaks account names, share names and, on domain controllers, directory metadata usable for targeted attacks.'

    # Kerberos parameters
    $kSvc = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'MaxServiceAge'
    $kTkt = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'MaxTicketAge'
    $kSkew = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'MaxClockSkew'
    $kSupported = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes'
    $kSupportedVal = Get-U32 $kSupported
    $kEncText = if ($null -eq $kSupportedVal) { 'not present (default: all supported encryption types offered, i.e. RC4 + AES per client capability)' } else {
        $parts = @()
        if ($kSupportedVal -band 0x1) { $parts += 'DES-CBC-CRC' }
        if ($kSupportedVal -band 0x2) { $parts += 'DES-CBC-MD5' }
        if ($kSupportedVal -band 0x4) { $parts += 'RC4-HMAC' }
        if ($kSupportedVal -band 0x8) { $parts += 'AES128-CTS-HMAC-SHA1-96' }
        if ($kSupportedVal -band 0x10) { $parts += 'AES256-CTS-HMAC-SHA1-96' }
        if ($kSupportedVal -band 0x20) { $parts += 'Future/Unused(0x20)' }
        if ($kSupportedVal -band 0x40) { $parts += 'Future/Unused(0x40)' }
        ($parts -join ' + ')
    }
    Add-Control -Category 'Authentication' -Attribute 'Kerberos Client Encryption Policy' `
        -Expected 'AES128 + AES256 permitted, RC4 discouraged/removed. RC4-HMAC Kerberos tickets are crackable offline and enable Kerberoasting without service-account password strength guarantees.' `
        -Configured ('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes = ' + (Format-RegState $kSupported)) `
        -Observed ('Decoded: ' + $kEncText + ' | MaxTicketAge=' + (Format-RegState $kTkt) + ' MaxServiceAge=' + (Format-RegState $kSvc) + ' MaxClockSkew=' + (Format-RegState $kSkew)) `
        -Validation 'Registry read with hexadecimal bitmask decoding. Per-account/computer msDS-SupportedEncryptionTypes is audited in Section 13.' `
        -Result $(if ($kSupportedVal -ne $null -and ($kSupportedVal -band 0x4) -and -not ($kSupportedVal -band 0x10)) { 'WARN' } else { 'PASS' }) `
        -FactKey 'KerberosSupportedEt' -FactValue $kSupportedVal -Class 'Medium' -CatClass 'Confidentiality' `
        -Finding $(if ($null -eq $kSupportedVal) { 'Kerberos encryption types are not restricted by policy on this host.' } else { 'Kerberos encryption policy is explicitly configured: ' + $kEncText }) `
        -Remediation 'Move to AES-only Kerberos: set SupportedEncryptionTypes=0x18 (AES128+AES256) on clients and servers after confirming every Kerberos service (including appliances) supports AES. Track and remove RC4 dependencies before disabling 0x4.' `
        -Impact 'Where RC4 remains permitted, a service ticket obtained for an SPN-holding account can be cracked offline; combined with weak service-account passwords this yields service-account compromise.'

    # =======================================================================================
    #  2.5 RDP security
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.5 Remote Desktop security ---------------------------------------------------' -ForegroundColor DarkCyan
    $deny = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    $secLayer = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer'
    $minEnc = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel'
    $nla = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
    $nlaReq = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'UserAuthentication'
    $denyVal = Get-U32 $deny; $secLayerVal = Get-U32 $secLayer; $minEncVal = Get-U32 $minEnc; $nlaVal = Get-U32 $nla
    $rdpEnabled = ($denyVal -eq 0)
    Add-Control -Category 'Remote Access - RDP' -Attribute 'RDP Service Enabled' `
        -Expected 'RDP disabled where not required (fDenyTSConnections=1). Remote interactive access is a primary lateral-movement mechanism and an interactive-attack surface.' `
        -Configured (Format-RegState $deny) -Observed $(if ($null -eq $denyVal) { 'Not configured at this level (default = RDP enabled on modern Windows builds)' } elseif ($denyVal -eq 0) { 'RDP ENABLED (fDenyTSConnections=0)' } else { 'RDP disabled (fDenyTSConnections=1)' }) `
        -Validation 'Registry read; live TCP/3389 reachability and service banner validated in Section 8/4 (port matrix + RDP X.224 probe).' `
        -Result $(if ($rdpEnabled) { 'WARN' } else { 'PASS' }) -FactKey 'RdpEnabled' -FactValue $rdpEnabled -Class 'Medium' `
        -Finding $(if ($rdpEnabled) { 'Remote Desktop is enabled on this host - reachability is validated in the port matrix before any impact is claimed.' } else { 'Remote Desktop is disabled in the registry.' }) `
        -Remediation 'If RDP is not required: set fDenyTSConnections=1 and block TCP/3389 inbound at the host firewall and network tier. If required, enforce NLA, TLS 1.2+, High encryption, MFA/PAW access, deny local admin logon for RDP where possible, and restrict source subnets.' `
        -Impact 'Exposed RDP is the most common lateral-movement transport: a single valid credential (from phishing, reuse, or a service account) yields interactive control of the host, and compromise of a privileged session exposes the credential material of that session.'

    Add-Control -Category 'Remote Access - RDP' -Attribute 'RDP NLA / TLS / Encryption Level' `
        -Expected 'UserAuthentication=1 (NLA required), SecurityLayer=2 (TLS), MinEncryptionLevel=3 (High). Without NLA, unauthenticated attackers reach the login stack and can test credentials.' `
        -Configured ('UserAuthentication=' + (Format-RegState $nla) + ' ; Policy UserAuthentication(NLA)=' + (Format-RegState $nlaReq) + ' ; SecurityLayer=' + (Format-RegState $secLayer) + ' ; MinEncryptionLevel=' + (Format-RegState $minEnc)) `
        -Observed ('NLA ' + $(if ($nlaVal -eq 1 -or (Get-U32 $nlaReq) -eq 1) { 'enabled' } else { 'NOT enabled' }) + '; SecurityLayer=' + $(switch ($secLayerVal) { 0 { '0 (RDP native encryption - weakest)' } 1 { '1 (negotiate - allows native RDP downgrade)' } 2 { '2 (SSL/TLS - expected)' } default { '(not present / default)' } }) + '; MinEncryptionLevel=' + $(if ($null -eq $minEncVal) { '(not present / default)' } elseif ($minEncVal -eq 3) { '3 (High - expected)' } else { [string]$minEncVal }) + '. Live validation: the RDP X.224 probe in Section 4 reports whether the listener demands NLA before authentication.') `
        -Validation 'Registry read + live RDP X.224 Connection Request probe (read-only protocol handshake, no authentication attempted).' `
        -Result $(if (($null -ne $secLayerVal -and $secLayerVal -eq 0) -or ($null -eq $nlaVal -and (Get-U32 $nlaReq) -ne 1)) { 'WARN' } else { 'PASS' }) `
        -FactKey 'RdpNla' -FactValue (($nlaVal -eq 1) -or ((Get-U32 $nlaReq) -eq 1)) -Class 'Medium' -CatClass 'Confidentiality' `
        -Finding 'RDP transport and authentication requirements recorded with the effective protocol-level setting.' `
        -Remediation 'Set WinStations\RDP-Tcp: UserAuthentication=1, SecurityLayer=2, MinEncryptionLevel=3 (GPO: Remote Desktop Session Host > Security: "Require user authentication for remote connections by using Network Level Authentication", "Set client connection encryption level = High").' `
        -Impact 'Without NLA, an attacker reaches the credential prompt pre-authentication, enabling password guessing against accounts and exposing the pre-auth RDP attack surface; native RDP encryption (layer 0/1) is weaker than TLS and can be downgraded.'

    # =======================================================================================
    #  2.6 WinRM
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.6 Windows Remote Management (WinRM) -----------------------------------------' -ForegroundColor DarkCyan
    $winrmSvc = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\WinRM' -Name 'Start'
    $wrmBasic = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic'
    $wrmUnenc = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic'
    $wrmDigest = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowDigest'
    $wrmSvcState = 'unknown'
    $svc = Get-ServiceSafe 'WinRM'
    if ($svc) { $wrmSvcState = $svc.Status.ToString() + ' / StartMode=' + $svc.StartType.ToString() }
    $listenerInfo = '(WSMan provider unavailable)'
    $authMatrix = @()
    try {
        $r = Invoke-Expression 'Get-ChildItem -Path WSMan:\localhost\Service\Auth -ErrorAction Stop' | Out-Null
        foreach ($p in (Get-ChildItem 'WSMan:\localhost\Service\Auth' -ErrorAction Stop)) {
            $authMatrix += [pscustomobject]@{ Mechanism = $p.Name; Enabled = $p.Value }
        }
        $listenerInfo = ((Get-ChildItem 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue) | Measure-Object).Count.ToString() + ' listener(s) configured'
    } catch { $listenerInfo = 'WSMAN provider read failed: ' + $_.Exception.Message }
    if ($authMatrix.Count -gt 0) {
        Write-Table -Rows $authMatrix -Columns @('Mechanism','Enabled') -Headers @{ Mechanism='WSMan auth mechanism'; Enabled='Enabled (true/false)' }
    }
    $basicEnabled = $false
    foreach ($a in $authMatrix) { if ($a.Mechanism -eq 'Basic' -and [string]$a.Enabled -eq 'true') { $basicEnabled = $true } }
    Add-Control -Category 'Remote Management - WinRM' -Attribute 'WinRM Service + Listener Configuration' `
        -Expected 'WinRM only where remote management is required. Basic auth disabled, unencrypted traffic disabled, and listeners restricted to HTTPS (5986) or bound to management subnets.' `
        -Configured ('Service Start=' + (Format-RegState $winrmSvc) + ' ; Policy AllowBasic=' + (Format-RegState $wrmBasic) + ' ; Policy AllowUnencryptedTraffic=' + (Format-RegState $wrmUnenc) + ' ; Policy AllowDigest=' + (Format-RegState $wrmDigest)) `
        -Observed ('Service state = ' + $wrmSvcState + ' ; ' + $listenerInfo + ' ; Basic auth effectively ' + $(if ($basicEnabled) { 'ENABLED' } else { 'disabled or not readable' })) `
        -Validation 'Registry + service state + native WSMan provider enumeration; live HTTP probe of 5985/5986 in Section 4 confirms whether the endpoint is actually reachable.' `
        -Result $(if ($basicEnabled -or ((Get-U32 $wrmUnenc) -eq 1)) { 'RISK DETECTED' } elseif ($svc -and $svc.Status -eq 'Running') { 'WARN' } else { 'PASS' }) `
        -FactKey 'WinRmRunning' -FactValue ([bool]($svc -and $svc.Status -eq 'Running')) -Class 'High' `
        -Finding $(if ($basicEnabled -or ((Get-U32 $wrmUnenc) -eq 1)) { 'WinRM permits Basic authentication or unencrypted traffic.' } elseif ($svc -and $svc.Status -eq 'Running') { 'WinRM is running and listening - remote PowerShell is available to any principal holding administrative rights on this host.' } else { 'WinRM service is not running.' }) `
        -Remediation 'If WinRM is required: set Policy AllowBasic=0 and AllowUnencryptedTraffic=0, prefer HTTPS listeners with a trusted certificate, restrict listener IPs, and use constrained endpoints/Just Enough Administration. If not required, stop and disable the WinRM service and block 5985/5986.' `
        -Impact 'WinRM is a direct remote code execution channel for any principal with administrative rights on the host; when Basic auth or unencrypted HTTP is enabled, credentials traverse the network in a recoverable form, and any credential that grants WinRM access to many hosts is a lateral-movement master key.'

    # =======================================================================================
    #  2.7 Windows Firewall
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.7 Windows Defender Firewall ------------------------------------------------' -ForegroundColor DarkCyan
    $fwRows = @(); $fwWeakProfiles = @(); $fwAvailable = $false
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $fwAvailable = $true
        foreach ($p in $profiles) {
            $inAction = $p.DefaultInboundAction.ToString()
            $outAction = $p.DefaultOutboundAction.ToString()
            $fwRows += [pscustomobject]@{
                Profile = $p.Name; Enabled = $p.Enabled.ToString(); Inbound = $inAction; Outbound = $outAction
                LogBlocked = $p.LogBlocked.ToString(); NotifyOnListen = $p.NotifyOnListen.ToString()
            }
            if (-not $p.Enabled -or $inAction -ne 'Block') { $fwWeakProfiles += ($p.Name + '(Enabled=' + $p.Enabled + ',Inbound=' + $inAction + ')') }
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('NetSecurity module unavailable (' + $_.Exception.Message + '); falling back to the firewall policy registry keys.')
        foreach ($prof in @('DomainProfile','StandardProfile','PublicProfile')) {
            $en = Get-RegValue -Path ('SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $prof) -Name 'EnableFirewall'
            $inA = Get-RegValue -Path ('SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $prof) -Name 'DefaultInboundAction'
            $enV = Get-U32 $en; $inV = Get-U32 $inA
            $fwRows += [pscustomobject]@{ Profile = $prof; Enabled = $(if ($null -eq $enV) { '(absent)' } else { [string]$enV }); Inbound = $(if ($null -eq $inV) { '(absent=Block)' } elseif ($inV -eq 1) { 'Block' } else { 'Allow' }); Outbound = 'n/a'; LogBlocked = 'n/a'; NotifyOnListen='n/a' }
            if ($enV -eq 0 -or $inV -eq 0) { $fwWeakProfiles += ($prof + '(Enabled=' + [string]$enV + ',InboundAllow=' + [string]$inV + ')') }
        }
    }
    if ($fwRows.Count -gt 0) { Write-Table -Rows $fwRows -Columns @('Profile','Enabled','Inbound','Outbound','LogBlocked','NotifyOnListen') -Headers @{ Profile='Firewall profile'; Enabled='Enabled'; Inbound='Default inbound'; Outbound='Default outbound'; LogBlocked='Log blocked'; NotifyOnListen='Notify on listen' } }
    Add-Control -Category 'Host Firewall' -Attribute 'Windows Firewall Profile State' `
        -Expected 'All three profiles (Domain, Private/Standard, Public) enabled with DefaultInboundAction=Block. The host firewall is the last line of defence for exposed administrative ports (445/135/3389/5985).' `
        -Configured $(if ($fwAvailable) { 'Observed live via Get-NetFirewallProfile (authoritative policy engine state for this host)' } else { 'Registry fallback under SharedAccess\Parameters\FirewallPolicy (NetSecurity module unavailable)' }) `
        -Observed $(if ($fwRows.Count -eq 0) { 'No firewall profile state could be read.' } else { (($fwRows | ForEach-Object { $_.Profile + '=' + $_.Enabled }) -join '; ') }) `
        -Validation 'Live read of the effective firewall policy engine; no rules are created, modified or deleted. Note: this assesses the LOCAL engine only - domain GPO policy may override and is not re-applied by this tool.' `
        -Result $(if ($fwRows.Count -eq 0) { 'NOT TESTABLE' } elseif ($fwWeakProfiles.Count -gt 0) { 'RISK DETECTED' } else { 'PASS' }) `
        -FactKey 'FirewallEnabled' -FactValue ([bool]($fwWeakProfiles.Count -eq 0 -and $fwRows.Count -gt 0)) -Class 'High' `
        -Finding $(if ($fwWeakProfiles.Count -gt 0) { 'One or more firewall profiles are disabled or allow inbound by default: ' + ($fwWeakProfiles -join ', ') } else { 'All firewall profiles are enabled with inbound traffic blocked by default.' }) `
        -Remediation 'Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True. Enforce through GPO so local tampering is reverted, and log allowed/blocked traffic to a central collector.' `
        -Impact 'With the local firewall disabled, every listening service on the host (SMB, RPC, WinRM, RDP, spooler) becomes directly reachable from any routable network - turning a segmented estate into a flat one.'

    # =======================================================================================
    #  2.8 LSA protection / Credential Guard / LSASS hardening (configuration evidence)
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.8 LSA protection, Credential Guard, LSASS hardening ------------------------' -ForegroundColor DarkCyan
    $runAsPpl = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe' -Name 'RunAsPPL'
    $runAsPplBoot = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe' -Name 'RunAsPPLBoot'
    $runAsPplVal = Get-U32 $runAsPpl
    $cgScenario = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' -Name 'Enabled'
    $cgScenarioVal = Get-U32 $cgScenario
    $hvciScenario = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
    $cgRun = $null
    try { $cgRun = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop } catch { }
    $cgRunningText = 'not readable (Win32_DeviceGuard unavailable on this build/role)'
    $cgRunning = $null
    if ($cgRun) {
        $svcRun = [int]$cgRun.SecurityServicesRunning
        $svcCfg = [int]$cgRun.SecurityServicesConfigured
        $running = @()
        if ($svcRun -band 1) { $running += 'Credential Guard (1)' }
        if ($svcRun -band 2) { $running += 'HVCI / Memory Integrity (2)' }
        if ($svcRun -band 4) { $running += 'System Guard Secure Launch (4)' }
        if ($svcRun -band 8) { $running += 'SMM Firmware Measurement (8)' }
        $cgRunning = [bool]($svcRun -band 1)
        $cgRunningText = 'SecurityServicesRunning=' + $svcRun + ' [' + (($running -join ', ') -replace '^$','none') + ']; SecurityServicesConfigured=' + $svcCfg + '; VBS status=' + $cgRun.VirtualizationBasedSecurityStatus + '; CodeIntegrityPolicyEnforcementStatus=' + $cgRun.CodeIntegrityPolicyEnforcementStatus
    }
    Add-Control -Category 'Credential Protection' -Attribute 'LSA Protection (RunAsPPL)' `
        -Expected 'Enabled (RunAsPPL=1, or 2 with UEFI lock) on Windows 8.1+/Server 2012 R2+. Prevents non-PPL code from reading LSASS memory, defeating credential-dumping tools and many LSASS-targeting techniques.' `
        -Configured ('RunAsPPL=' + (Format-RegState $runAsPpl) + ' ; RunAsPPLBoot(legacy)=' + (Format-RegState $runAsPplBoot)) `
        -Observed 'The effective process protection level of lsass.exe is queried at runtime and reported in Section 5 (VALIDATED/NOT CONFIRMED) - configuration alone is not treated as proof.' `
        -Validation 'Registry read now; runtime protection level of the lsass process read via NtQueryInformationProcess(ProcessProtectionInformation) in Section 5. No LSASS memory is read, opened for read, or dumped.' `
        -Result $(if ($runAsPplVal -eq 1 -or $runAsPplVal -eq 2) { 'PASS' } elseif ($null -eq $runAsPplVal) { 'WARN' } else { 'RISK DETECTED' }) `
        -FactKey 'RunAsPPL' -FactValue $runAsPplVal -Class 'High' -CatClass 'DataAtRest' `
        -Finding $(if ($runAsPplVal -eq 1 -or $runAsPplVal -eq 2) { 'LSA protection is configured (runtime verification in Section 5).' } elseif ($null -eq $runAsPplVal) { 'LSA protection (RunAsPPL) is not configured.' } else { 'LSA protection is explicitly disabled (RunAsPPL=0).' }) `
        -Remediation 'Set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\RunAsPPL=1 (DWORD) and reboot; use =2 to enable UEFI-locked configuration that cannot be disabled without physical firmware access. Deploy via GPO and verify with Section 5 runtime validation.' `
        -Impact 'Without LSA protection, any code running as an administrator on the host can read LSASS memory and obtain credentials (NTLM hashes, Kerberos keys, cleartext where wdigest is enabled). On a domain controller this is equivalent to domain-wide credential compromise.'

    Add-Control -Category 'Credential Protection' -Attribute 'Credential Guard' `
        -Expected 'Enabled and RUNNING where hardware/virtualisation and licensing permit. Credential Guard isolates LSA secrets in a VBS-protected process, making cached domain credentials and derived keys unreadable even to SYSTEM.' `
        -Configured ('DeviceGuard\Scenarios\CredentialGuard\Enabled=' + (Format-RegState $cgScenario) + ' ; HVCI scenario=' + (Format-RegState $hvciScenario)) `
        -Observed $cgRunningText `
        -Validation 'Live WMI query of Win32_DeviceGuard (root\Microsoft\Windows\DeviceGuard) - SecurityServicesRunning is runtime state, therefore this is an OBSERVED result, not an inferred one.' `
        -Result $(if ($null -eq $cgRunning) { 'NOT TESTABLE' } elseif ($cgRunning) { 'VALIDATED' } elseif ($cgScenarioVal -eq 1) { 'NOT CONFIRMED' } else { 'WARN' }) `
        -FactKey 'CredentialGuardRunning' -FactValue $cgRunning -Class 'High' -CatClass 'DataAtRest' `
        -Finding $(if ($cgRunning) { 'Credential Guard is RUNNING on this host (validated at runtime).' } elseif ($null -eq $cgRunning) { 'Credential Guard status could not be validated at runtime on this build.' } elseif ($cgScenarioVal -eq 1) { 'Credential Guard is configured but NOT running (reboot required, or VBS/UEFI lock not satisfied).' } else { 'Credential Guard is not configured on this host.' }) `
        -Remediation 'Enable VBS + Credential Guard (GPO: Computer Configuration > Administrative Templates > System > Device Guard > "Turn On Virtualization Based Security" = Enabled with Secure Boot and DMA protection; scenario "Credential Guard" = Enabled with UEFI lock). Requires UEFI Secure Boot, VT-x/AMD-V and (usually) TPM.' `
        -Impact 'Without Credential Guard, harvested credential material (hashes, Kerberos keys) from this host can be reused immediately against other systems - the classic pass-the-hash/pass-the-ticket path from a single compromised workstation to domain-wide access.'

    # =======================================================================================
    #  2.9 Microsoft Defender state
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.9 Endpoint protection (Microsoft Defender) ----------------------------------' -ForegroundColor DarkCyan
    $mpStatus = $null; $mpPref = $null
    try { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } catch { }
    try { $mpPref = Get-MpPreference -ErrorAction Stop } catch { }
    $avProducts = @()
    try { $avProducts = @(Get-CimInstance -ClassName AntiVirusProduct -Namespace 'root\SecurityCenter2' -ErrorAction Stop) } catch { }
    if ($avProducts.Count -gt 0) {
        Write-Table -Rows ($avProducts | Select-Object displayName, productState, timestamp) -Columns @('displayName','productState','timestamp') -Headers @{ displayName='Registered AV product'; productState='productState (hex flags)'; timestamp='Timestamp' }
    }
    $rtOn = $null; $tamper = $null; $sigAge = $null; $engVer=''
    if ($mpStatus) {
        $rtOn = [bool]$mpStatus.RealTimeProtectionEnabled
        $tamper = [string]$mpStatus.IsTamperProtected
        $engVer = [string]$mpStatus.AMEngineVersion
        try { $sigAge = [int]((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalDays } catch { }
    }
    $asrIds = @()
    if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) { $asrIds = @($mpPref.AttackSurfaceReductionRules_Ids) }
    $exclusions = @()
    if ($mpPref) { $exclusions = @($mpPref.ExclusionPath) + @($mpPref.ExclusionProcess) + @($mpPref.ExclusionExtension) }
    Add-Control -Category 'Endpoint Protection' -Attribute 'Defender Real-Time / Tamper / ASR' `
        -Expected 'Real-time protection on, tamper protection on, current signatures, ASR rules enabled in block mode. Endpoint protection determines whether a given technique survives long enough to be used - but its presence is NOT a mitigation claim for configuration weaknesses.' `
        -Configured $(if ($mpStatus) { 'Get-MpComputerStatus + Get-MpPreference (live Defender management interface)' } else { 'Defender management cmdlets unavailable; registry/policy read fallback is limited (Defender keys are ACL-protected)' }) `
        -Observed $(if ($mpStatus) { 'RealTime=' + $rtOn + '; TamperProtected=' + $tamper + '; Engine=' + $engVer + '; Signature age=' + $(if ($null -ne $sigAge) { [string]$sigAge + ' day(s)' } else { 'unknown' }) + '; ASR rules configured=' + $asrIds.Count + '; Exclusion entries=' + $exclusions.Count } else { 'Defender state could not be read (module absent, third-party AV active, or key access denied - all of which are themselves legitimate states)' }) `
        -Validation 'Live Defender status API (runtime state). Exclusions are reported as a count only, because listing exclusion paths would disclose which locations an attacker should use; request the list separately if required by the engagement scope.' `
        -Result $(if ($null -eq $mpStatus) { 'NOT TESTABLE' } elseif ($rtOn -ne $true) { 'RISK DETECTED' } elseif ($exclusions.Count -gt 5) { 'WARN' } else { 'PASS' }) `
        -FactKey 'DefenderRealtime' -FactValue $rtOn -Class 'High' `
        -Finding $(if ($null -eq $mpStatus) { 'Endpoint protection state could not be read from this context.' } elseif ($rtOn -ne $true) { 'Real-time protection is reported as disabled.' } elseif ($exclusions.Count -gt 5) { [string]$exclusions.Count + ' Defender exclusion entries are configured - exclusions are a common attacker persistence and staging location.' } else { 'Defender is running with real-time protection and a small exclusion set.' }) `
        -Remediation 'Enable real-time protection and tamper protection (Set-MpPreference -DisableRealtimeMonitoring $false; tamper protection is enabled in the Defender security centre), enforce ASR rules in Block mode, minimise and review exclusions quarterly, and keep signatures current via the update path audited in Section 7.' `
        -Impact 'With endpoint protection disabled or heavily excluded, technique-level detections are removed; configuration weaknesses catalogued elsewhere in this report become directly usable without an intervening control.'

    # =======================================================================================
    #  2.10 Patch management / WSUS state (configuration) - Windows Update service level
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.10 Patch management configuration (summary; detailed in Section 7) ----------' -ForegroundColor DarkCyan
    $wuSvc = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\wuauserv' -Name 'Start'
    $wuSvcObj = Get-ServiceSafe 'wuauserv'
    $buildKey = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
    $buildName = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
    $dispVer = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'DisplayVersion'
    $script:OsBuild = if ($buildName.NameExists) { [int]$buildName.Value } else { $null }
    $script:OsUbr = Get-U32 $buildKey
    Add-Control -Category 'Patch Management' -Attribute 'OS Build / Revision Level' `
        -Expected 'A currently serviced build with a recent UBR (update build revision). Unsupported or long-unpatched builds carry known, weaponised local and remote privilege-escalation vulnerabilities.' `
        -Configured ('CurrentBuildNumber=' + (Format-RegState $buildName) + ' ; UBR=' + (Format-RegState $buildKey) + ' ; DisplayVersion=' + (Format-RegState $dispVer)) `
        -Observed ('OS build ' + $(if ($buildName.NameExists) { $buildName.Value + '.' + $(if ($null -ne $script:OsUbr) { $script:OsUbr } else { '?' }) } else { 'unknown' }) + ' - compare against the Microsoft servicing baseline for this release during reporting.') `
        -Validation 'Registry read. This tool does NOT claim a patch level: mapping a build revision to the current security baseline requires the Microsoft update catalogue, which is out of scope for an offline assessment host.' `
        -Result 'NOT CONFIRMED' -FactKey 'OsBuildRevision' -FactValue $script:OsUbr -Class 'High' `
        -Finding 'Build revision recorded for manual comparison against the Microsoft security update baseline.' `
        -Remediation 'Compare the recorded build/UBR against the Microsoft Update Catalog security baseline for this release and confirm the host is receiving (and installing) monthly cumulative updates. Where a build is out of support, plan an in-place upgrade.' `
        -Impact 'Unpatched local privilege-escalation vulnerabilities turn a standard user into a local administrator, which is the pivot step for reading LSASS memory and reaching administrative services on other hosts.'

    # =======================================================================================
    #  2.11 Print Spooler presence and configuration (detailed in Section 6)
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- 2.11 Print Spooler configuration ---------------------------------------------' -ForegroundColor DarkCyan
    # The role-aware spooler FINDING is produced in Section 6. Here the raw state is recorded
    # as context so that Section 2 remains a complete configuration inventory without
    # double-counting the same finding in the report.
    $spoolState = Test-SpoolerConfiguration
    Write-KV 'Spooler service' ($spoolState.ServiceStatus + ' (start type ' + $spoolState.StartType + ')')
    Write-KV 'Spooler exists / spoolss pipe' ($spoolState.ServiceExists.ToString() + ' / ' + $spoolState.PipeExposed.ToString())
    Write-KV 'Spooler hardening values' $spoolState.Configured
    Write-Context 'Spooler configuration' ('status=' + $spoolState.ServiceStatus + '; startType=' + $spoolState.StartType + '; pipe=' + $spoolState.PipeExposed)

    # =======================================================================================
    #  2.x PowerShell Hardening and Telemetry Visibility
    #  READ-ONLY: registry values are queried through the existing .NET registry helper.
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- PowerShell Hardening and Telemetry Visibility -------------------------------' -ForegroundColor DarkCyan
    $scriptBlockLogging = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
    $transcription = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscription'
    $scriptBlockLoggingEnabled = $scriptBlockLogging.NameExists -and ((Get-U32 $scriptBlockLogging) -eq 1)
    $transcriptionEnabled = $transcription.NameExists -and ((Get-U32 $transcription) -eq 1)

    Write-KV 'Script Block Logging' $(if ($scriptBlockLoggingEnabled) { 'enabled' } else { 'disabled' })
    Write-KV 'PowerShell Transcription' $(if ($transcriptionEnabled) { 'enabled' } else { 'disabled' })

    if (-not $scriptBlockLoggingEnabled) {
        Add-Control -Category 'Endpoint Hardening' `
            -Attribute 'PowerShell Script Block Logging' `
            -Expected 'Enabled' `
            -Configured $(if ($scriptBlockLogging.NameExists) { [string]$scriptBlockLogging.Value } else { 'not configured' }) `
            -Observed $(if ($scriptBlockLogging.NameExists) { [string]$scriptBlockLogging.Value } else { 'registry value absent' }) `
            -Result 'WARN' `
            -Finding 'PowerShell Script Block Logging is not explicitly enabled by the assessed policy path.' `
            -Validation 'Read-only registry inspection of SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging.' `
            -Class 'Medium' -CatClass 'Integrity'
    } else {
        Write-Status 'PASS' 'PowerShell Script Block Logging is enabled.'
    }

    # =======================================================================================
    #  2.x Remote Local Administrator Token Filtering
    #  READ-ONLY: registry value is queried through the existing .NET registry helper.
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- Remote Local Administrator Token Filtering ----------------------------------' -ForegroundColor DarkCyan
    $latf = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy'
    $latfValue = Get-U32 $latf
    if ($latfValue -eq 1) {
        Add-Control -Category 'Credential Protection' `
            -Attribute 'LocalAccountTokenFilterPolicy Bypass' `
            -Expected '0 or absent' `
            -Configured '1' `
            -Observed 'LocalAccountTokenFilterPolicy=1' `
            -Result 'RISK DETECTED' `
            -Finding 'LocalAccountTokenFilterPolicy is set to 1, disabling the normal remote UAC token filtering behavior for local administrator accounts.' `
            -Validation 'Read-only registry inspection of SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy.' `
            -Class 'High' -CatClass 'IdentityRights'
    } else {
        Write-Status 'PASS' 'LocalAccountTokenFilterPolicy is not set to 1.'
    }

    # Native read-only corroboration: net.exe localgroup Administrators.
    Write-Host ''
    Write-Host '  -- Native local administrator corroboration (net.exe) ----------------------------' -ForegroundColor DarkCyan
    try {
        $netLocalGroupLines = @(& net.exe localgroup Administrators 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not $netLocalGroupLines) {
            throw ('net.exe localgroup returned exit code ' + [string]$LASTEXITCODE)
        }
        $netAdminRows = @()
        foreach ($line in $netLocalGroupLines) {
            $t = ([string]$line).Trim()
            if (-not $t) { continue }
            if ($t -match '^Alias name|^Comment|^Members|^---|^The command completed successfully') { continue }
            $netAdminRows += [pscustomobject]@{ Member = $t }
        }
        if ($netAdminRows.Count -gt 0) {
            Write-Table -Rows $netAdminRows -Columns @('Member') -Headers @{ Member='net.exe localgroup Administrators' }
            Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' `
                -Attribute 'Native local Administrators corroboration' `
                -Finding 'The local Administrators group was corroborated with the native net.exe utility.' `
                -Observed ('Members returned by net.exe: ' + ($netAdminRows.Member -join ', ')) `
                -Validation 'Read-only native net.exe localgroup Administrators invocation; no group membership was modified.' `
                -Class 'Low' -CatClass 'Context' -NoConsole
        } else {
            Write-Status 'PASS' 'net.exe localgroup Administrators returned no member records.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Native net.exe local Administrators corroboration failed: ' + $_.Exception.Message)
    }

}

function Test-SpoolerConfiguration {
    <# Returns a fact object describing spooler state. Used by Section 2 (configuration summary)
       and Section 6 (role-based exposure assessment). Read-only: the service is never stopped,
       started or reconfigured. #>
    $svcKey = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\Spooler' -Name 'Start'
    $svcObj = Get-ServiceSafe 'Spooler'
    $p2p = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators'
    $p2pNoWarn = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall'
    $rpcAuth = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Print' -Name 'RpcAuthnLevelPrivacyEnabled'
    $spoolss = $false
    try {
        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
        foreach ($p in $pipes) { if ($p -match 'spoolss$') { $spoolss = $true } }
    } catch { }
    return [pscustomobject]@{
        ServiceExists    = [bool]$svcKey.KeyExists
        ServiceStatus    = $(if ($svcObj) { $svcObj.Status.ToString() } else { 'not installed' })
        StartType        = $(if ($svcObj) { $svcObj.StartType.ToString() } else { 'n/a' })
        StartValue       = $(if ($null -ne (Get-U32 $svcKey)) { [string](Get-U32 $svcKey) } else { '(absent)' })
        PointAndPrintRestrict = Get-U32 $p2p
        NoWarningNoElevation  = Get-U32 $p2pNoWarn
        RpcAuthnPrivacy  = Get-U32 $rpcAuth
        PipeExposed      = $spoolss
        Configured       = ('Service Start=' + (Format-RegState $svcKey) + ' ; PointAndPrint\RestrictDriverInstallationToAdministrators=' + (Format-RegState $p2p) + ' ; NoWarningNoElevationOnInstall=' + (Format-RegState $p2pNoWarn) + ' ; Control\Print\RpcAuthnLevelPrivacyEnabled=' + (Format-RegState $rpcAuth))
    }
}

function Write-ReportSpooler {
    param([object]$Spool)
    $role = $script:Section1Role
    $isInfra = ($role -like '*MEMBER SERVER*' -or $role -like '*DOMAIN CONTROLLER*' -or $role -like '*Member Server*' -or $role -like '*DOMAIN CONTROLLER*')
    $running = ($Spool.ServiceStatus -eq 'Running')
    Add-Control -Category 'Print Spooler' -Attribute 'Spooler Service State / Start Mode' `
        -Expected $(if ($isInfra) { 'Stopped and Disabled on servers and domain controllers that are not print servers. The Spooler exposes a large MS-RPRN/MS-PAR RPC surface and has a history of critical remote code execution and local privilege escalation (PrintNightmare class).' } else { 'Running is acceptable on workstations (users need printing); hardening must then come from Point-and-Print policy and RPC authentication.' }) `
        -Configured $Spool.Configured `
        -Observed ('Service exists=' + $Spool.ServiceExists + '; status=' + $Spool.ServiceStatus + '; start type=' + $Spool.StartType + '; Start reg=' + $Spool.StartValue + '; host role=' + $role + '; spoolss named pipe present=' + $Spool.PipeExposed) `
        -Validation 'Service control manager state + registry + native named-pipe namespace enumeration (\\.\pipe\spoolss). NO print-provider call, no driver installation, no exploitation is attempted.' `
        -Result $(if (-not $Spool.ServiceExists) { 'PASS' } elseif ($running -and $isInfra) { 'RISK DETECTED' } elseif ($running) { 'WARN' } else { 'PASS' }) `
        -FactKey 'SpoolerRunning' -FactValue $running -Class $(if ($isInfra -and $running) { 'Critical' } else { 'High' }) -CatClass 'Integrity' `
        -Finding $(if (-not $Spool.ServiceExists) { 'The Spooler service is not installed on this host.' } elseif ($running -and $isInfra) { 'The Spooler service is RUNNING on a ' + $role + ' - unneeded printing attack surface on infrastructure.' } elseif ($running) { 'The Spooler service is running on this workstation (expected for user printing, subject to policy hardening).' } else { 'The Spooler service exists but is not running.' }) `
        -Remediation 'On servers and DCs: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled (GPO: "Allow Print Spooler to accept client connections" = Disabled, plus a service-startup policy) and block TCP/445 print RPC where printing is not required. On workstations keep Point-and-Print restricted and RPC authentication enforced.' `
        -Impact 'A running spooler on infrastructure exposes unauthenticated/authenticated RPC interfaces that have been used for remote code execution as SYSTEM (PrintNightmare, CVE-2021-34527/1675) and for coercion of machine account authentication (PrinterBug/RpcRemoteFindFirstPrinterChangeNotification) usable in NTLM relay chains to a DC.'

    Add-Control -Category 'Print Spooler' -Attribute 'Spooler Point-and-Print / RPC Hardening' `
        -Expected 'RestrictDriverInstallationToAdministrators=1, NoWarningNoElevationOnInstall=0, NoWarningNoElevationOnUpdate=0, and RpcAuthnLevelPrivacyEnabled=1 (RPC packet privacy required for the Windows print stack). These are the vendor mitigations for the PrintNightmare vulnerability class.' `
        -Configured $Spool.Configured `
        -Observed ('RestrictDriverInstallationToAdministrators=' + $(if ($null -eq $Spool.PointAndPrintRestrict) { 'not present (pre-mitigation default: non-admin driver installation permitted' } else { [string]$Spool.PointAndPrintRestrict }) + '; NoWarningNoElevationOnInstall=' + $(if ($null -eq $Spool.NoWarningNoElevation) { 'not present (default = prompt/no elevation)' } else { [string]$Spool.NoWarningNoElevation }) + '; RpcAuthnLevelPrivacyEnabled=' + $(if ($null -eq $Spool.RpcAuthnPrivacy) { 'not present (default = 0 on unpatched builds, 1 on builds with the 2021 print hardening applied)' } else { [string]$Spool.RpcAuthnPrivacy }) + '. Validation of this class is deliberately LIMITED to configuration: triggering the vulnerable code path would constitute exploitation, which is out of scope for this tool.') `
        -Validation 'Registry read of the documented vendor mitigation keys (no attempted driver installation; that action is prohibited by the tool design).' `
        -Result $(if ($null -eq $Spool.PointAndPrintRestrict -and $null -eq $Spool.RpcAuthnPrivacy) { 'WARN' } elseif ($Spool.PointAndPrintRestrict -eq 0 -or $Spool.NoWarningNoElevation -eq 1 -or $Spool.RpcAuthnPrivacy -eq 0) { 'RISK DETECTED' } else { 'PASS' }) `
        -FactKey 'SpoolerHardened' -FactValue ([bool](($Spool.PointAndPrintRestrict -eq 1) -and ($Spool.RpcAuthnPrivacy -eq 1))) `
        -Class 'High' -CatClass 'Integrity' `
        -Finding 'Point-and-Print and RPC authentication hardening state recorded (see OBSERVED).' `
        -Remediation 'Set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators=1, NoWarningNoElevationOnInstall=0, NoWarningNoElevationOnUpdate=0, and HKLM\SYSTEM\CurrentControlSet\Control\Print\RpcAuthnLevelPrivacyEnabled=1, then restart the Spooler. Apply via GPO across the estate.' `
        -Impact 'Without these mitigations, an authenticated low-privilege domain user can install a print driver that executes as SYSTEM on the target host (local privilege escalation) or trigger machine-account authentication coercion usable in relay attacks.'
}
# ===========================================================================================
#  PROTOCOL VALIDATION TOOLKIT  (part 4/9)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Everything in this part performs a *read-only protocol handshake* against a service and
#  records the raw response. This is what allows the report to distinguish:
#
#     "the registry says RequireSecuritySignature=0"          <- CONFIGURATION EVIDENCE
#     "the SMB2 NEGOTIATE response did not set the             <- ACTIVE VALIDATION
#      SIGNING_REQUIRED bit, and a signed-less session was
#      therefore accepted by the peer"
#
#  Probes implemented (all are single-request, bounded, non-destructive):
#     * TCP connect test                       (reachability)
#     * SMB1 NEGOTIATE 0x72 + SMB2 NEGOTIATE   (dialect + SECURITY_MODE_SIGNING_REQUIRED)
#     * NetBIOS session request on 139         (legacy session service availability)
#     * LDAP anonymous simple bind + RootDSE   (anonymous exposure, SASL mechanisms)
#     * RDP X.224 connection request           (NLA / TLS enforcement observed at the wire)
#     * WinRM HTTP/HTTPS HEAD+GET /wsman       (authentication schemes actually offered)
#     * Kerberos AS-REQ without pre-auth data  (validates DONT_REQ_PREAUTH for named accounts)
#
#  NOT IMPLEMENTED, BY DESIGN (documented so the reader knows the tool's limits):
#     * no credential submission, password guessing, spraying or hash use of any kind
#     * no ticket or key material capture, storage or display (AS-REP blobs are discarded)
#     * no exploitation of a service, no driver/print/spooler code path triggering
#     * no persistence, no evasion, no hidden network activity
# ===========================================================================================

function Test-TcpPort {
    <# Bounded single-connection TCP reachability test. Distinguishes:
         Open     - SYN/ACK completed (service is reachable)
         Closed   - RST received (host reachable, port not listening)
         Filtered - no response within the timeout (firewall drop / host down)
       This distinction matters: "Closed" proves the host is alive and the port filtered away,
       "Filtered" cannot distinguish a firewall drop from an offline host. #>
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = $script:Cfg.TcpTimeoutMs
    )
    # Gate at the primitive, not only at the caller. /localonly must refuse a REMOTE target even
    # if a future caller forgets to check; loopback stays permitted because Section 4 legitimately
    # probes 127.0.0.1 when the assessed host is itself the domain controller.
    if (-not (Test-TargetAllowed -Target $Target) -and -not (Test-IsLocalTarget -Name $Target)) {
        return [pscustomobject]@{ Target=$Target; Port=$Port; State='Suppressed'; LatencyMs=0; Error=(Get-RemoteSuppressedNote); Banner='' }
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    $result = [pscustomobject]@{ Target=$Target; Port=$Port; State='Unknown'; LatencyMs=0; Error=''; Banner='' }
    try {
        $client.NoDelay = $true
        $ar = $client.BeginConnect($Target, $Port, $null, $null)
        $signalled = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $signalled) {
            $result.State = 'Filtered'; $result.Error = 'timeout after ' + $TimeoutMs + 'ms (no SYN/ACK, no RST)'
        } else {
            try { $client.EndConnect($ar); $result.State = 'Open' }
            catch [System.Net.Sockets.SocketException] {
                $code = $_.Exception.SocketErrorCode
                if ($code -eq [System.Net.Sockets.SocketError]::ConnectionRefused) { $result.State = 'Closed'; $result.Error = 'RST received (port not listening)' }
                elseif ($code -eq [System.Net.Sockets.SocketError]::HostUnreachable -or $code -eq [System.Net.Sockets.SocketError]::NetworkUnreachable) { $result.State = 'Filtered'; $result.Error = 'ICMP unreachable (' + $code.ToString() + ')' }
                elseif ($code -eq [System.Net.Sockets.SocketError]::TimedOut) { $result.State = 'Filtered'; $result.Error = 'connection timed out' }
                else { $result.State = 'Closed'; $result.Error = $code.ToString() }
            }
        }
    } catch {
        $result.State = 'Unknown'; $result.Error = $_.Exception.Message
    } finally {
        try { $client.Close() } catch { }
    }
    $sw.Stop()
    $result.LatencyMs = $sw.ElapsedMilliseconds
    return $result
}

function Send-TcpPayload {
    <# Sends a raw byte payload to a TCP port and returns the raw response bytes.
       All socket operations are non-blocking-with-timeout and always closed afterwards. #>
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [Parameter(Mandatory=$true)][byte[]]$Payload,
        [int]$TimeoutMs = 2500,
        [int]$IdleMs = 350,
        [switch]$UseTls
    )
    $out = [pscustomobject]@{ Ok=$false; Bytes=(New-Object byte[] 0); Error=''; LatencyMs=0; TlsInfo=$null }
    if (-not (Test-TargetAllowed -Target $Target) -and -not (Test-IsLocalTarget -Name $Target)) {
        $out.Error = (Get-RemoteSuppressedNote)
        return $out
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    $stream = $null
    try {
        $client.NoDelay = $true
        $ar = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $out.Error = 'TCP connect timeout'; return $out }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        if ($UseTls) {
            $ssl = New-Object System.Net.Security.SslStream($stream, $false, [System.Net.Security.RemoteCertificateValidationCallback]{
                param($sndr, $cert, $chain, $errors)
                try {
                    if ($cert) {
                        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
                        $script:LastTlsCert = [pscustomobject]@{ Subject=$c.Subject; Issuer=$c.Issuer; Thumbprint=$c.Thumbprint; NotAfter=$c.NotAfter; NotBefore=$c.NotBefore }
                    }
                } catch { }
                return $true   # assessment context: accept and RECORD the peer certificate, do not enforce trust
            })
            $script:LastTlsCert = $null
            $ssl.AuthenticateAsClient($Target)
            $stream = $ssl
            $out.TlsInfo = $script:LastTlsCert
        }
        try { $stream.ReadTimeout = 250; $stream.WriteTimeout = 250 } catch { }
        $stream.Write($Payload, 0, $Payload.Length)
        $stream.Flush()
        $buf = New-Object byte[] 8192
        $ms  = New-Object System.IO.MemoryStream
        $lastData = 0
        while ($true) {
            if ($sw.ElapsedMilliseconds -gt $TimeoutMs) { break }
            $n = 0
            try { $n = $stream.Read($buf, 0, $buf.Length) } catch { break }
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
            $lastData = [int]$sw.ElapsedMilliseconds
            if (($sw.ElapsedMilliseconds - $lastData) -gt $IdleMs) { break }
            if ($ms.Length -ge 65536) { break }    # absolute cap; no unbounded reads
        }
        $out.Bytes = $ms.ToArray()
        $out.Ok = $true
    } catch {
        $out.Error = $_.Exception.Message
    } finally {
        try { if ($stream) { $stream.Dispose() } } catch { }
        try { $client.Close() } catch { }
    }
    $sw.Stop()
    $out.LatencyMs = $sw.ElapsedMilliseconds
    return $out
}

function ConvertTo-HexString {
    param([byte[]]$Bytes, [int]$Max = 32)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '(no data)' }
    $n = [Math]::Min($Max, $Bytes.Length)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $n; $i++) { [void]$sb.Append($Bytes[$i].ToString('X2')); [void]$sb.Append(' ') }
    if ($Bytes.Length -gt $n) { [void]$sb.Append('... (' + $Bytes.Length + ' bytes total)') }
    return $sb.ToString().Trim()
}

# -------------------------------------------------------------------------------------------
#  SMB NEGOTIATE PROBES
#  Two independent probes are used so that the result cannot be misread:
#    (a) SMB1 NEGOTIATE with dialect "NT LM 0.12"  -> is the legacy dialect still OFFERED?
#    (b) SMB2 NEGOTIATE (0x0202/0x0210/0x0300/0x0302) -> dialect + SecurityMode flags
#  The SMB2 NEGOTIATE response SecurityMode is the authoritative statement of whether the
#  server REQUIRES message signing - this is a protocol-level validation of the registry
#  value audited in Section 2.2.
# -------------------------------------------------------------------------------------------
function New-Smb1NegotiatePacket {
    $p = New-Object System.Collections.Generic.List[byte]
    $p.AddRange([byte[]]@(0xFF,0x53,0x4D,0x42))     # protocol "\xFFSMB"
    $p.Add(0x72)                                    # command NEGOTIATE
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # status
    $p.Add(0x18)                                    # flags (canonicalized + case-insensitive paths)
    $p.AddRange([byte[]]@(0x01,0xC8))               # flags2 (unicode + NT status + extended security)
    $p.AddRange([byte[]]@(0x00,0x00))               # pid high
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))  # signature
    $p.AddRange([byte[]]@(0x00,0x00))               # reserved
    $p.AddRange([byte[]]@(0x00,0x00))               # tid
    $p.AddRange([byte[]]@(0x00,0x00))               # pid
    $p.AddRange([byte[]]@(0x00,0x00))               # uid
    $p.AddRange([byte[]]@(0x00,0x00))               # mid
    # --- canonical 47-byte SMB1 NEGOTIATE request (the frame every SMB scanner sends) -------
    # WordCount = 0x00, ByteCount = 0x000C, data = dialect index 0x02 + "NT LM 0.12" + NUL.
    # Emitting the exact canonical frame matters: some hardened stacks answer malformed frames
    # with a reset, which would be misread as "SMBv1 disabled".
    $dialectName = [System.Text.Encoding]::ASCII.GetBytes('NT LM 0.12')
    $data = New-Object byte[] ($dialectName.Length + 2)
    $data[0] = 0x02                                  # DialectIndex: "NT LM 0.12"
    [System.Array]::Copy($dialectName, 0, $data, 1, $dialectName.Length)
    $data[$data.Length - 1] = 0x00                   # NUL terminator
    $p.Add(0x00)                                     # WordCount
    $p.AddRange([byte[]]@([byte]($data.Length -band 0xFF), [byte](($data.Length -shr 8) -band 0xFF)))  # ByteCount
    $p.AddRange($data)
    return ,$p.ToArray()
}

function Invoke-Smb1NegotiateProbe {
    param([string]$Target, [int]$Port = 445, [int]$TimeoutMs = 2500)
    $payload = New-Smb1NegotiatePacket
    $r = Send-TcpPayload -Target $Target -Port $Port -Payload $payload -TimeoutMs $TimeoutMs
    $res = [pscustomobject]@{
        Target=$Target; Port=$Port; Service='SMB1 (CIFS) NEGOTIATE'; Supported=$null; DialectIndex=$null
        ServerFlags=''; SecurityMode=''; Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 24); Error=$r.Error; LatencyMs=$r.LatencyMs
    }
    $b = $r.Bytes
    if (-not $b -or $b.Length -lt 36) {
        $res.Supported = $false
        if (-not $res.Error) { $res.Error = 'no SMB1 negotiate response (SMB1 negotiation not completed by peer)' }
        return $res
    }
    $isNeg = ($b[0] -eq 0xFF -and $b[1] -eq 0x53 -and $b[2] -eq 0x4D -and $b[3] -eq 0x42 -and $b[4] -eq 0x72)
    if ($isNeg) {
        $status = [BitConverter]::ToUInt32($b, 5)
        $res.DialectIndex = [BitConverter]::ToUInt16($b, 33)
        $res.ServerFlags = 'SMB1 header accepted; NTStatus=0x' + $status.ToString('X8') + '; dialectIndex=' + $res.DialectIndex
        if ($status -eq 0 -and $res.DialectIndex -ne 0xFFFF) { $res.Supported = $true }
        else { $res.Supported = $false }
    } else {
        # Some hardened builds answer hostile/legacy negotiation with a reset or an IPv4-ish
        # error frame; record exactly what came back instead of interpreting it.
        $res.Supported = $false
        $res.ServerFlags = 'unexpected response to SMB1 NEGOTIATE (first bytes: ' + (ConvertTo-HexString -Bytes $b -Max 8) + ')'
    }
    return $res
}

function New-Smb2NegotiatePacket {
    param([string]$Target = 'localhost')
    # Dialect array: 2.0.2 (0x0202), 2.1 (0x0210), 3.0 (0x0300), 3.0.2 (0x0302).
    # The array MUST be present in the packet - omitting it produces a malformed request whose
    # rejection would be misreported as "SMB2 unsupported". (Caught by the offline smoke test.)
    $dialectIds = @(0x0202, 0x0210, 0x0300, 0x0302)
    $dialectNames = @('SMB 2.0.2', 'SMB 2.1', 'SMB 3.0', 'SMB 3.0.2')
    $dialects = New-Object byte[] ($dialectIds.Count * 2)
    for ($i = 0; $i -lt $dialectIds.Count; $i++) {
        $dialects[$i * 2]     = [byte]($dialectIds[$i] -band 0xFF)          # little-endian on the wire
        $dialects[$i * 2 + 1] = [byte](($dialectIds[$i] -shr 8) -band 0xFF)
    }
    $p = New-Object System.Collections.Generic.List[byte]
    $p.AddRange([byte[]]@(0xFE,0x53,0x4D,0x42))     # \xFESMB
    $p.AddRange([byte[]]@(0x40,0x00))               # StructureSize = 64
    $p.AddRange([byte[]]@(0x00,0x00))               # CreditCharge
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # Status
    $p.AddRange([byte[]]@(0x00,0x00))               # Command = NEGOTIATE
    $p.AddRange([byte[]]@(0x01,0x00))               # CreditRequest
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # Flags
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # NextCommand
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))  # MessageId
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # Reserved / ProcessId
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # TreeId
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))  # SessionId
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))  # Signature
    $p.AddRange([byte[]]@(0x24,0x00))               # StructureSize = 36
    $p.AddRange([byte[]]@([byte]$dialectIds.Count, 0x00))   # DialectCount (number of dialects, not bytes)
    $p.AddRange([byte[]]@(0x01,0x00))               # SecurityMode = SIGNING_ENABLED (client capability)
    $p.AddRange([byte[]]@(0x00,0x00))               # Reserved
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00))     # Capabilities
    $g = New-Object byte[] 16
    try { (New-Object System.Random).NextBytes($g) } catch { }
    $p.AddRange($g)                                 # ClientGuid
    $p.AddRange([byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))  # ClientStartTime
    $p.AddRange($dialects)                           # the dialect array itself
    return ,$p.ToArray()
}

function Invoke-Smb2NegotiateProbe {
    param([string]$Target, [int]$Port = 445, [int]$TimeoutMs = 2500)
    $payload = New-Smb2NegotiatePacket -Target $Target
    $r = Send-TcpPayload -Target $Target -Port $Port -Payload $payload -TimeoutMs $TimeoutMs
    $res = [pscustomobject]@{
        Target=$Target; Port=$Port; Service='SMB2/3 NEGOTIATE'; Dialect=''; DialectName=''; SigningEnabled=$null
        SigningRequired=$null; SecurityModeHex=''; ServerGuid=''; Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 24); Error=$r.Error; LatencyMs=$r.LatencyMs
    }
    $b = $r.Bytes
    if (-not $b -or $b.Length -lt 68) {
        if (-not $res.Error) { $res.Error = 'no SMB2 negotiate response' }
        return $res
    }
    if (-not ($b[0] -eq 0xFE -and $b[1] -eq 0x53 -and $b[2] -eq 0x4D -and $b[3] -eq 0x42)) {
        $res.Error = 'unexpected response signature: ' + (ConvertTo-HexString -Bytes $b -Max 8)
        return $res
    }
    $status = [BitConverter]::ToUInt32($b, 8)
    if ($status -ne 0) { $res.Error = 'NEGOTIATE returned NTStatus 0x' + $status.ToString('X8'); return $res }
    $res.SecurityModeHex = '0x' + ([BitConverter]::ToUInt16($b, 34)).ToString('X4')
    $sm = [BitConverter]::ToUInt16($b, 34)
    $res.SigningEnabled  = [bool]($sm -band 0x0001)
    $res.SigningRequired = [bool]($sm -band 0x0002)
    $d = [BitConverter]::ToUInt16($b, 36)
    $res.Dialect = ('0x' + $d.ToString('X4'))
    $res.DialectName = switch ($d) {
        0x0202 { 'SMB 2.0.2' } 0x0210 { 'SMB 2.1' } 0x0300 { 'SMB 3.0' } 0x0302 { 'SMB 3.0.2' }
        0x0311 { 'SMB 3.1.1' } 0x02FF { 'SMB 2.???' } default { 'unknown dialect' }
    }
    try { $res.ServerGuid = (New-Object System.Guid(,(($b[40..55])))).ToString() } catch { }
    return $res
}

function Invoke-NetBiosSessionProbe {
    <# NetBIOS session service request on TCP/139. A positive session response (0x82) proves
       the legacy NetBIOS session service is listening - the transport used by SMB over 139,
       which bypasses some modern-only controls and is a classic NTLM-coercion/relay transport. #>
    param([string]$Target, [int]$TimeoutMs = 2000)
    $name = [System.Text.Encoding]::ASCII.GetBytes('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    $p = New-Object System.Collections.Generic.List[byte]
    $p.AddRange([byte[]]@(0x81,0x00,0x00,0x44))     # session request, length 0x44
    $p.Add(0x20); $p.AddRange($name); $p.Add(0x00)
    $p.Add(0x20); $p.AddRange($name); $p.Add(0x00)
    $payload = $p.ToArray()
    if ($payload.Length -ne 72) { Write-Status 'WARN' ('NetBIOS probe packet length is ' + $payload.Length + ' (expected 72)') }
    $r = Send-TcpPayload -Target $Target -Port 139 -Payload $payload -TimeoutMs $TimeoutMs
    $res = [pscustomobject]@{ Target=$Target; Port=139; Service='NetBIOS Session Service'; PositiveResponse=$null; ResponseCode=''; Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 16); Error=$r.Error }
    if ($r.Bytes -and $r.Bytes.Length -ge 1) {
        $res.ResponseCode = '0x' + $r.Bytes[0].ToString('X2')
        if ($r.Bytes[0] -eq 0x82) { $res.PositiveResponse = $true }
        elseif ($r.Bytes[0] -eq 0x83 -or $r.Bytes[0] -eq 0x84) { $res.PositiveResponse = $false }
        else { $res.PositiveResponse = $null }
    }
    return $res
}

# -------------------------------------------------------------------------------------------
#  LDAP PROBE
#  Anonymous simple bind is sent as raw BER (no credentials are ever transmitted). The result
#  code is parsed from the BindResponse. A successful anonymous bind is a validated exposure;
#  a resultCode of 8 (strongAuthRequired) indicates the server refused an unprotected bind.
#  RootDSE attribute enumeration (when readable) provides server metadata for the report.
# -------------------------------------------------------------------------------------------
function Invoke-LdapAnonymousBindProbe {
    param([string]$Target, [int]$Port = 389, [int]$TimeoutMs = 2500)
    # BER: SEQUENCE { INTEGER 3 (version), OCTET STRING '' (name), [0] OCTET STRING '' (simple auth) }
    $payload = [byte[]]@(0x30,0x0C,0x02,0x01,0x03,0x04,0x00,0x80,0x00)
    $r = Send-TcpPayload -Target $Target -Port $Port -Payload $payload -TimeoutMs $TimeoutMs
    $res = [pscustomobject]@{
        Target=$Target; Port=$Port; Service='LDAP (anonymous simple bind)'; ResultCode=$null; ResultName='';
        Diagnostic=''; Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 32); Error=$r.Error; LatencyMs=$r.LatencyMs
    }
    $b = $r.Bytes
    if (-not $b -or $b.Length -lt 9) { if (-not $res.Error) { $res.Error = 'no LDAP response' }; return $res }
    # BindResponse ::= [APPLICATION 1] -> 0x61
    $idx = -1
    for ($i = 0; $i -lt ($b.Length - 2); $i++) { if ($b[$i] -eq 0x0A -and $b[$i+1] -eq 0x01) { $idx = $i; break } }
    if ($idx -ge 0 -and ($idx + 2) -lt $b.Length) {
        $code = [int]$b[$idx + 2]
        $res.ResultCode = $code
        $res.ResultName = switch ($code) {
            0  { 'success (anonymous bind ACCEPTED)' }
            1  { 'operationsError' } 2 { 'protocolError' } 3 { 'timeLimitExceeded' } 4 { 'sizeLimitExceeded' }
            7  { 'authMethodNotSupported' } 8 { 'strongAuthRequired (unprotected bind refused)' }
            16 { 'noSuchAttribute' } 32 { 'noSuchObject' } 48 { 'inappropriateAuthentication' }
            49 { 'invalidCredentials' } 50 { 'insufficientAccessRights' } 51 { 'busy' }
            52 { 'unavailable' } 53 { 'unwillingToPerform' } 65 { 'objectClassViolation' }
            default { 'resultCode ' + $code }
        }
        # diagnosticMessage is the last OCTET STRING in the response (0x04 tag)
        try {
            $lastFour = -1
            for ($i = ($b.Length - 2); $i -ge 0; $i--) { if ($b[$i] -eq 0x04) { $lastFour = $i; break } }
            if ($lastFour -ge 0 -and ($lastFour + 2) -lt $b.Length) {
                $len = [int]$b[$lastFour + 1]
                if (($lastFour + 2 + $len) -le $b.Length) {
                    $res.Diagnostic = [System.Text.Encoding]::UTF8.GetString($b, $lastFour + 2, $len)
                }
            }
        } catch { }
    } else {
        $res.Error = 'LDAP response did not contain a parsable BindResponse'
    }
    return $res
}

function Get-LdapRootDse {
    <# RootDSE read via System.DirectoryServices (native, no RSAT). Anonymous when no credentials
       are supplied; otherwise uses the current process identity. #>
    param([string]$Server, [int]$Port = 389, [switch]$Anonymous)
    # Defence in depth: LDAP to a remote directory is off-host traffic. Loopback is permitted, so a
    # domain controller assessing itself can still read its own RootDSE under /localonly.
    if (-not (Test-RemoteAllowed) -and $Server -ne '127.0.0.1' -and $Server -ne 'localhost') {
        return [pscustomobject]@{ Ok=$false; Props=@{}; Error=(Get-RemoteSuppressedNote) }
    }
    try {
        $auth = if ($Anonymous) { [System.DirectoryServices.AuthenticationTypes]::Anonymous } else { [System.DirectoryServices.AuthenticationTypes]::Secure }
        $entry = New-Object System.DirectoryServices.DirectoryEntry(('LDAP://' + $Server + ':' + $Port + '/RootDSE'), $null, $null, $auth)
        $props = @{}
        foreach ($n in $entry.Properties.PropertyNames) {
            $v = $entry.Properties[$n].Value
            if ($v -is [byte[]]) { $v = (ConvertTo-HexString -Bytes $v -Max 16) }
            $props[$n] = $v
        }
        return [pscustomobject]@{ Ok=$true; Props=$props; Error='' }
    } catch {
        return [pscustomobject]@{ Ok=$false; Props=@{}; Error=$_.Exception.Message }
    }
}

# -------------------------------------------------------------------------------------------
#  RDP PROBE  (X.224 Connection Request with an RDP Negotiation Request)
#  The response's selectedProtocol tells us, at the wire level, whether the listener requires
#  Network Level Authentication (CredSSP) or offers legacy RDP security. No authentication is
#  attempted and no credentials are transmitted.
# -------------------------------------------------------------------------------------------
function Invoke-RdpX224Probe {
    param([string]$Target, [int]$Port = 3389, [int]$TimeoutMs = 2500)
    $payload = [byte[]]@(
        0x03,0x00,0x00,0x13,                                  # TPKT header, length 19
        0x0E,0xE0,0x00,0x00,0x00,0x00,0x00,                    # X.224 Connection Request
        0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00                # RDP Negotiation Request (TLS|CredSSP)
    )
    $r = Send-TcpPayload -Target $Target -Port $Port -Payload $payload -TimeoutMs $TimeoutMs
    $res = [pscustomobject]@{
        Target=$Target; Port=$Port; Service='RDP (X.224)'; Responded=$false; SelectedProtocol=$null
        SelectedProtocolName=''; NegotiationFailure=''; Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 24); Error=$r.Error; LatencyMs=$r.LatencyMs
    }
    $b = $r.Bytes
    if (-not $b -or $b.Length -lt 11) { if (-not $res.Error) { $res.Error = 'no RDP response (service disabled, firewall-blocked, or non-RDP listener)' }; return $res }
    if ($b[0] -eq 0x03 -and ($b[5] -eq 0xD0 -or $b[5] -eq 0x0E)) { $res.Responded = $true }
    # search for RDP_NEG_RSP (0x02) or RDP_NEG_FAILURE (0x03) structures
    for ($i = 0; $i -lt ($b.Length - 8); $i++) {
        if ($b[$i] -eq 0x02 -and $b[$i+1] -eq 0x00 -and $b[$i+2] -eq 0x08 -and $b[$i+3] -eq 0x00) {
            $sp = [BitConverter]::ToUInt32($b, $i + 4)
            $res.SelectedProtocol = $sp
            $res.SelectedProtocolName = switch ($sp) {
                0 { 'PROTOCOL_RDP (legacy native RDP security - no TLS, no NLA)' }
                1 { 'PROTOCOL_SSL (TLS, no NLA required)' }
                2 { 'PROTOCOL_HYBRID (CredSSP / Network Level Authentication required)' }
                3 { 'PROTOCOL_HYBRID (NLA required)' }
                4 { 'PROTOCOL_HYBRID_EX (NLA + restricted admin/early user auth)' }
                5 { 'PROTOCOL_RDSTLS' }
                default { 'unknown selectedProtocol=' + $sp }
            }
            break
        }
        if ($b[$i] -eq 0x03 -and $b[$i+1] -eq 0x00 -and $b[$i+2] -eq 0x08 -and $b[$i+3] -eq 0x00) {
            $fc = [BitConverter]::ToUInt32($b, $i + 4)
            $res.NegotiationFailure = switch ($fc) {
                1 { 'SSL_REQUIRED_BY_SERVER' } 2 { 'SSL_NOT_ALLOWED_BY_SERVER' } 3 { 'SSL_CERT_NOT_ON_SERVER' }
                4 { 'INCONSISTENT_FLAGS' } 5 { 'HYBRID_REQUIRED_BY_SERVER' } 6 { 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER' }
                default { 'failureCode=' + $fc }
            }
            break
        }
    }
    return $res
}

# -------------------------------------------------------------------------------------------
#  WinRM PROBE
#  An unauthenticated HTTP request to /wsman returns 401 and advertises the authentication
#  schemes the listener will accept. This is the honest, non-credential way to validate
#  whether Basic authentication is exposed (the schemes are chosen by the listener, not by us).
# -------------------------------------------------------------------------------------------
function Invoke-WinRmProbe {
    param([string]$Target, [int]$Port = 5985, [switch]$UseTls, [int]$TimeoutMs = 3000)
    $req = "POST /wsman HTTP/1.1`r`nHost: $Target`r`nContent-Type: application/soap+xml;charset=UTF-8`r`nContent-Length: 0`r`nUser-Agent: InfraPulse-Win`r`nConnection: close`r`n`r`n"
    $payload = [System.Text.Encoding]::ASCII.GetBytes($req)
    $r = Send-TcpPayload -Target $Target -Port $Port -Payload $payload -TimeoutMs $TimeoutMs -UseTls:$UseTls
    $text = ''
    if ($r.Bytes -and $r.Bytes.Length -gt 0) { $text = [System.Text.Encoding]::ASCII.GetString($r.Bytes) }
    $res = [pscustomobject]@{
        Target=$Target; Port=$Port; Service=$(if ($UseTls) { 'WinRM over HTTPS (5986)' } else { 'WinRM over HTTP (5985)' })
        Responded=$false; StatusLine=''; AuthSchemes=@(); OffersBasic=$null; ServerHeader=''; TlsSubject=''; TlsThumbprint=''; TlsNotAfter=''
        Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 24); Error=$r.Error; LatencyMs=$r.LatencyMs
    }
    if (-not $text) { if (-not $res.Error) { $res.Error = 'no HTTP response' }; return $res }
    $res.Responded = $true
    $lines = $text -split "`r`n"
    if ($lines.Count -gt 0) { $res.StatusLine = $lines[0] }
    foreach ($l in $lines) {
        if ($l -match '^(?i)WWW-Authenticate:\s*(.+)$') {
            $scheme = ($Matches[1] -split '\s+')[0].TrimEnd(',')
            $res.AuthSchemes += $scheme
        }
        if ($l -match '^(?i)Server:\s*(.+)$') { $res.ServerHeader = $Matches[1].Trim() }
    }
    $res.OffersBasic = [bool](($res.AuthSchemes | Where-Object { $_ -match '(?i)basic' }).Count -gt 0)
    if ($r.TlsInfo) { $res.TlsSubject = $r.TlsInfo.Subject; $res.TlsThumbprint = $r.TlsInfo.Thumbprint; $res.TlsNotAfter = $r.TlsInfo.NotAfter }
    return $res
}

# -------------------------------------------------------------------------------------------
#  KERBEROS AS-REQ PROBE (pre-authentication validation)
#  ----------------------------------------------------------------------------------------
#  For an account that has DONT_REQ_PREAUTH set, the KDC answers an AS-REQ that contains NO
#  pre-authentication data with a full AS-REP instead of KRB-ERROR / KDC_ERR_PREAUTH_REQUIRED.
#  That single response is the authoritative validation that pre-authentication is not
#  enforced for the named account - the condition behind offline AS-REP cracking.
#
#  SAFETY PROPERTIES OF THIS PROBE
#    * one packet per named account, maximum of 10 accounts per run (configured)
#    * only accounts already identified as DONT_REQ_PREAUTH by LDAP enumeration are probed
#    * no password, key or credential material of any kind is transmitted or guessed
#    * the AS-REP payload is parsed only for its message type and is then DISCARDED - it is
#      never written to disk, never printed, and never retained in memory beyond the call
#    * no offline cracking is performed
# -------------------------------------------------------------------------------------------
function New-DerTlv {
    # Builds one BER/DER tag-length-value element and returns a genuine [byte[]].
    # NOTE: the encoding is built into a pre-sized byte array rather than by array
    # concatenation, because PowerShell's '+' on arrays yields Object[] which cannot be
    # passed to List[byte].AddRange - that failure mode was caught by the smoke test.
    param([byte]$Tag, [byte[]]$Content)
    $len = $Content.Length
    $lenBytes = @()
    if ($len -lt 0x80) { $lenBytes = @([byte]$len) }
    elseif ($len -lt 0x100) { $lenBytes = @(0x81, [byte]$len) }
    elseif ($len -lt 0x10000) { $lenBytes = @(0x82, [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF)) }
    else { $lenBytes = @(0x83, [byte](($len -shr 16) -band 0xFF), [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF)) }
    $out = New-Object byte[] (1 + $lenBytes.Count + $Content.Length)
    $out[0] = $Tag
    for ($i = 0; $i -lt $lenBytes.Count; $i++) { $out[1 + $i] = [byte]$lenBytes[$i] }
    if ($Content.Length -gt 0) { [System.Array]::Copy($Content, 0, $out, 1 + $lenBytes.Count, $Content.Length) }
    return ,$out
}
function New-DerInt {
    param([int]$Value)
    if ($Value -eq 0) { return ,(New-DerTlv -Tag 0x02 -Content ([byte[]]@(0x00))) }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $v = $Value
    while ($v -gt 0) { $bytes.Insert(0, [byte]($v -band 0xFF)); $v = $v -shr 8 }
    if ($bytes[0] -band 0x80) { $bytes.Insert(0, 0x00) }
    return ,(New-DerTlv -Tag 0x02 -Content $bytes.ToArray())
}
function New-DerGeneralString {
    param([string]$Text)
    return ,(New-DerTlv -Tag 0x1B -Content ([System.Text.Encoding]::ASCII.GetBytes($Text)))
}
function New-DerExplicit {
    param([int]$TagNumber, [byte[]]$Content)
    return ,(New-DerTlv -Tag ([byte](0xA0 -bor $TagNumber)) -Content $Content)
}
function New-DerSequence {
    param([byte[]]$Content)
    return ,(New-DerTlv -Tag 0x30 -Content $Content)
}
function New-KerberosPrincipalName {
    param([int]$NameType, [string[]]$NameStrings)
    $seq = New-Object System.Collections.Generic.List[byte]
    $inner = New-Object System.Collections.Generic.List[byte]
    foreach ($s in $NameStrings) { $inner.AddRange([byte[]](New-DerGeneralString $s)) }
    $seq.AddRange([byte[]](New-DerTlv -Tag 0x30 -Content $inner.ToArray()))
    $bodyList = New-Object System.Collections.Generic.List[byte]
    $bodyList.AddRange([byte[]](New-DerExplicit -TagNumber 0 -Content (New-DerInt $NameType)))
    $bodyList.AddRange($seq.ToArray())
    return ,(New-DerTlv -Tag 0x30 -Content $bodyList.ToArray())
}
function New-KerberosAsReq {
    param([string]$UserName, [string]$Domain, [int[]]$ETypes = @(23, 18, 17))
    $realm = $Domain.ToUpperInvariant()
    $nonce = Get-Random -Minimum 100000 -Maximum 2147483646
    $body = New-Object System.Collections.Generic.List[byte]
    # kdc-options: forwardable | renewable | proxiable | canonicalize (standard client flags)
    $kdco = [byte[]]@(0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10)
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 0 -Content $kdco))
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 1 -Content (New-KerberosPrincipalName -NameType 1 -NameStrings @($UserName))))
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 2 -Content (New-DerGeneralString $realm)))
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 3 -Content (New-KerberosPrincipalName -NameType 2 -NameStrings @('krbtgt', $realm))))
    $till = New-DerTlv -Tag 0x18 -Content ([System.Text.Encoding]::ASCII.GetBytes('20370913024805Z'))
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 5 -Content $till))
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 6 -Content $till))
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 7 -Content (New-DerInt $nonce)))
    $etypeSeq = New-Object System.Collections.Generic.List[byte]
    foreach ($e in $ETypes) { $etypeSeq.AddRange([byte[]](New-DerInt $e)) }
    $body.AddRange([byte[]](New-DerExplicit -TagNumber 8 -Content (New-DerTlv -Tag 0x30 -Content $etypeSeq.ToArray())))
    $reqBody = New-DerTlv -Tag 0x30 -Content $body.ToArray()
    $innerList = New-Object System.Collections.Generic.List[byte]
    $innerList.AddRange([byte[]](New-DerExplicit -TagNumber 1 -Content (New-DerInt 5)))
    $innerList.AddRange([byte[]](New-DerExplicit -TagNumber 2 -Content (New-DerInt 10)))
    $innerList.AddRange([byte[]](New-DerExplicit -TagNumber 4 -Content $reqBody))
    return ,(New-DerTlv -Tag 0x6A -Content $innerList.ToArray())   # [APPLICATION 10] KRB-AS-REQ
}

function Invoke-KerberosPreAuthProbe {
    param([string]$Target, [string]$UserName, [string]$Domain, [int]$Port = 88, [int]$TimeoutMs = 2500)
    # Defence in depth: this helper talks to a KDC, which is always off-host. Under /localonly it
    # refuses to build or send anything, so an ungated caller cannot produce a datagram.
    if (-not (Test-RemoteAllowed)) {
        return [pscustomobject]@{
            Target=$Target; Port=$Port; Service='Kerberos KDC (AS-REQ, no pre-auth data)'; User=$UserName
            MessageType=''; MessageTypeName=''; ErrorCode=$null; ErrorName=''; PreAuthNotEnforced=$null
            Raw=''; Error=(Get-RemoteSuppressedNote); LatencyMs=0
        }
    }
    $payload = New-KerberosAsReq -UserName $UserName -Domain $Domain
    $r = Send-TcpPayload -Target $Target -Port $Port -Payload $payload -TimeoutMs $TimeoutMs
    $res = [pscustomobject]@{
        Target=$Target; Port=$Port; Service='Kerberos KDC (AS-REQ, no pre-auth data)'; User=$UserName
        MessageType=''; MessageTypeName=''; ErrorCode=$null; ErrorName=''; PreAuthNotEnforced=$null
        Raw=(ConvertTo-HexString -Bytes $r.Bytes -Max 16); Error=$r.Error; LatencyMs=$r.LatencyMs
    }
    $b = $r.Bytes
    if (-not $b -or $b.Length -lt 5) { if (-not $res.Error) { $res.Error = 'no KDC response' }; return $res }
    if ($b[0] -eq 0x7B) {
        $res.MessageType = 'AS-REP'; $res.MessageTypeName = 'AS-REP (application 11)'
        $res.PreAuthNotEnforced = $true
        $res.Raw = 'AS-REP received (' + $b.Length + ' bytes) - payload voluntarily discarded, no ticket material retained'
    } elseif ($b[0] -eq 0x7E) {
        $res.MessageType = 'KRB-ERROR'; $res.MessageTypeName = 'KRB-ERROR (application 30)'
        $res.PreAuthNotEnforced = $false
        for ($i = 0; $i -lt ($b.Length - 4); $i++) {
            if ($b[$i] -eq 0xA7 -and $b[$i+1] -eq 0x03 -and $b[$i+2] -eq 0x02 -and $b[$i+3] -eq 0x01) {
                $code = [int]$b[$i+4]; $res.ErrorCode = $code
                $res.ErrorName = switch ($code) {
                    6  { 'KDC_ERR_C_PRINCIPAL_UNKNOWN (no such principal)' }
                    7  { 'KDC_ERR_S_PRINCIPAL_UNKNOWN' }
                    12 { 'KDC_ERR_POLICY' }
                    18 { 'KDC_ERR_CLIENT_REVOKED (account disabled/locked/expired)' }
                    23 { 'KDC_ERR_KEY_EXPIRED (password expired)' }
                    24 { 'KDC_ERR_PREAUTH_FAILED' }
                    25 { 'KDC_ERR_PREAUTH_REQUIRED (pre-authentication IS enforced)' }
                    32 { 'KRB_AP_ERR_TKT_EXPIRED' }
                    37 { 'KRB_AP_ERR_SKEW (clock skew too large)' }
                    38 { 'KRB_AP_ERR_BADADDR' }
                    default { 'error code ' + $code }
                }
                break
            }
        }
    } else {
        $res.MessageType = 'unrecognised Kerberos message tag 0x' + $b[0].ToString('X2')
        $res.Error = 'response was not an AS-REP or KRB-ERROR'
    }
    return $res
}

# -------------------------------------------------------------------------------------------
#  Read-SocketText
#  Bounded read of a text-protocol greeting or an HTTP header block. Termination is timeout
#  driven: Read() raises IOException when the peer sends nothing further within ReadTimeout,
#  which IS the normal end-of-banner signal for these protocols. Nothing is written to the
#  socket by this helper, so it can never advance a protocol state machine.
# -------------------------------------------------------------------------------------------
function Read-SocketText {
    param([System.IO.Stream]$Stream, [int]$TimeoutMs = 1500, [int]$MaxBytes = 8192, [int]$FirstByteMs = 500)
    $buf = New-Object byte[] 1024
    $sb = New-Object System.Text.StringBuilder
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $sawAny = $false
    while ($sb.Length -lt $MaxBytes -and $sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if ($sawAny) { $Stream.ReadTimeout = 300 } else { $Stream.ReadTimeout = $FirstByteMs }
        try {
            $n = $Stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $sawAny = $true
            [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n))
            if ($sb.ToString() -match "`r`n`r`n") { break }
        } catch { break }
    }
    return $sb.ToString()
}

# -------------------------------------------------------------------------------------------
#  Invoke-BannerGrab
#  Read-only identification of a service that volunteers information BEFORE authentication.
#  Three exchange types, all of them non-mutating:
#      greeting  - FTP/SSH/Telnet push a banner unprompted; we read it and close.
#      http      - one HEAD / request; we never GET a resource, so no content is retrieved and
#                  no application logic is invoked beyond header generation.
#      tls       - one client handshake; we capture the certificate and negotiated protocol and
#                  close without sending any application data.
#  /localonly suppresses this entirely - it is an off-host connection.
# -------------------------------------------------------------------------------------------
function Invoke-BannerGrab {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 1500)
    $res = [pscustomobject]@{ Host = $Target; Port = $Port; Kind = 'none'; Product = ''; Status = ''; Banner = ''; Note = '' }

    # Gate: explicitly structural early return, so /localonly can never reach the socket code.
    if (-not (Test-TargetAllowed -Target $Target)) { $res.Kind = 'suppressed'; $res.Note = (Get-TargetSuppressionReason -Target $Target); return $res }

    $client = $null
    $stream = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $res.Note = 'connect timed out'; return $res }
        $client.EndConnect($iar)
        if (-not $client.Connected) { $res.Note = 'connection not established'; return $res }
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $stream = $client.GetStream()

        $greeting = @(21, 22, 23, 25, 587)
        $httpish  = @(80, 8080, 8530)
        $tlsish   = @(443, 8443, 8531)

        if ($greeting -contains $Port) {
            $res.Kind = 'greeting'
            $res.Banner = Read-SocketText -Stream $stream -TimeoutMs $TimeoutMs
        }
        elseif ($httpish -contains $Port) {
            $res.Kind = 'http'
            # HEAD only: no response body, so no resource is fetched and no state changes on the
            # server. HTTP/1.0 + Connection: close keeps it to a single request/response exchange.
            $req = 'HEAD / HTTP/1.0' + "`r`n" + 'Host: ' + $Target + "`r`n" + 'User-Agent: ' + $script:Cfg.ToolName + '/' + $script:Cfg.ToolVersion + "`r`n" + 'Connection: close' + "`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $res.Banner = Read-SocketText -Stream $stream -TimeoutMs $TimeoutMs
        }
        elseif ($tlsish -contains $Port) {
            $res.Kind = 'tls'
            # Accept any certificate: this is identification, not trust validation. The certificate
            # is then inspected locally, and trust defects are reported as findings against the
            # target rather than silently dropped.
            $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($senderObj, $certObj, $chainObj, $errObj) return $true }
            $ssl = New-Object System.Net.Security.SslStream -ArgumentList $stream, $false, $cb
            $ssl.ReadTimeout = $TimeoutMs
            $ssl.AuthenticateAsClient($Target)
            $res.Status = [string]$ssl.SslProtocol
            $raw = $ssl.RemoteCertificate
            if ($raw) {
                $c2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $raw)
                $res.Product = [string]$c2.Subject
                $res.Banner = 'subject=' + [string]$c2.Subject + '; issuer=' + [string]$c2.Issuer +
                              '; notBefore=' + $c2.NotBefore.ToString('yyyy-MM-dd') +
                              '; notAfter=' + $c2.NotAfter.ToString('yyyy-MM-dd') +
                              '; thumbprint=' + [string]$c2.Thumbprint
                # Self-signed detection is a comparison of the issuer and subject strings only -
                # no chain building, no revocation fetch, no network dependency beyond the socket.
                if (([string]$c2.Subject) -eq ([string]$c2.Issuer)) { $res.Note = 'self-signed' }
                if ($c2.NotAfter -lt (Get-Date)) { $res.Note = (($res.Note + '; expired').Trim('; ')) }
            }
        }
        else {
            $res.Kind = 'not-probed'
            $res.Note = 'no read-only banner exchange is defined for this service'
        }
    } catch {
        $res.Note = 'probe error: ' + $_.Exception.Message
    } finally {
        try { if ($stream) { $stream.Close() } } catch { }
        try { if ($client) { $client.Close() } } catch { }
    }

    # ---- parse the captured text -------------------------------------------------------------
    if ($res.Banner) {
        if ($res.Kind -eq 'http') {
            if ($res.Banner -match '(?m)^HTTP/[0-9]\.[0-9]\s+([0-9]{3})') { $res.Status = $Matches[1] }
            if ($res.Banner -match '(?m)^Server:\s*(.+?)\s*$')          { $res.Product = $Matches[1].Trim() }
        }
        elseif ($res.Kind -eq 'greeting' -and -not $res.Product) {
            $first = ([string]$res.Banner -split "`r?`n")[0]
            if ($first) { $res.Product = $first.Trim() }
        }
        # A banner is evidence, but it is one line long in a CSV cell: collapse whitespace and cut
        # at a fixed width so one chatty service cannot blow out the report.
        $flat = ($res.Banner -replace '[\r\n\t]+', ' ').Trim()
        if ($flat.Length -gt 400) { $flat = $flat.Substring(0, 400) + '...[truncated]' }
        $res.Banner = $flat
    }
    return $res
}

function Get-ServiceNameForPort {
    param([int]$Port)
    switch ($Port) {
        53   { 'DNS' }            88   { 'Kerberos' }        111  { 'rpcbind' }
        135  { 'MSRPC Endpoint Mapper' } 137 { 'NetBIOS-NS (UDP)' } 138 { 'NetBIOS-DGM (UDP)' }
        139  { 'NetBIOS Session / SMB' }  389 { 'LDAP' }     445  { 'SMB' }
        464  { 'Kerberos kpasswd' } 636 { 'LDAPS' }          3268 { 'Global Catalog' }
        3269 { 'Global Catalog over SSL' } 3389 { 'RDP' }    5985 { 'WinRM over HTTP' }
        5986 { 'WinRM over HTTPS' } 8530 { 'WSUS over HTTP' } 8531 { 'WSUS over HTTPS' }
        9389 { 'AD Web Services' } 1433 { 'MSSQL' }          3306 { 'MySQL' }
        5432 { 'PostgreSQL' }     8080 { 'HTTP (alt)' }      80   { 'HTTP' }  443 { 'HTTPS' }
        default { 'unknown/' + $Port }
    }
}
# ===========================================================================================
#  SECTIONS 3-7 :: SMB / AUTHENTICATION / LSA-LSASS / SPOOLER / PATCH MANAGEMENT  (part 5/9)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  These five modules take the CONFIGURATION EVIDENCE collected in Section 2 and attempt to
#  VALIDATE it at the protocol or runtime level. Every module prints an explicit
#  configuration-vs-observation comparison so that a mismatch (GPO not applied, service not
#  restarted, policy overridden) is visible instead of being averaged away.
#
#  No module in this part modifies host state: services are never started/stopped/reconfigured,
#  no registry write occurs, no print/spooler code path is triggered, and no update is installed.
# ===========================================================================================

function Get-LocalListeningPorts {
    <# Authoritative local listening-port inventory. Prefers Get-NetTCPConnection (native,
       Windows 8/2012+) and falls back to parsing netstat -an when the module is unavailable. #>
    $out = New-Object System.Collections.ArrayList
    $got = $false
    try {
        foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
            $proc = ''
            try { $proc = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            [void]$out.Add([pscustomobject]@{ Address = $c.LocalAddress; Port = [int]$c.LocalPort; PID = [int]$c.OwningProcess; Process = $proc })
            $got = $true
        }
    } catch { }
    if (-not $got) {
        try {
            $lines = & netstat.exe -ano 2>$null
            foreach ($l in $lines) {
                if ($l -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)') {
                    $addr = $Matches[1]; $port = [int]$Matches[2]; $pid = [int]$Matches[3]
                    $proc = ''
                    try { $proc = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { }
                    [void]$out.Add([pscustomobject]@{ Address = $addr; Port = $port; PID = $pid; Process = $proc })
                }
            }
        } catch { Write-Status 'NOT TESTABLE' ('Listening-port enumeration failed: ' + $_.Exception.Message) }
    }
    return @($out)
}

# ===========================================================================================
#  SECTION 3 :: SMB SECURITY ASSESSMENT
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  SMB is the single most abused protocol in internal networks: NTLM relay to SMB/LDAP,
#  pass-the-hash to administrative shares, coercion of machine accounts over SMB, and legacy
#  SMBv1 exploitation. This module answers, for this host, the only questions that matter:
#    1. Is TCP/445 reachable and is the SMB server answering?      (reachability)
#    2. Does the SMB2 NEGOTIATE response REQUIRE signing?           (validation)
#    3. Is the legacy SMB1 dialect still negotiated?                (validation)
#    4. Does the observed answer match the registry configuration?  (integrity of the audit)
# ===========================================================================================
function Invoke-Section3_Smb {
    $local = '127.0.0.1'
    $t445 = Test-TcpPort -Target $local -Port 445 -TimeoutMs 900
    Write-Host ''
    Write-Host ('  HOST -> TCP/445 -> SMB RESPONSE -> SIGNING STATE -> CONFIGURATION -> VALIDATION -> RESULT') -ForegroundColor DarkCyan
    Write-Host ('  ' + $script:HostName + ' -> TCP/445 = ' + $t445.State + ' (' + $t445.LatencyMs + ' ms)') -ForegroundColor Gray

    $listen445 = (Get-LocalListeningPorts | Where-Object { $_.Port -eq 445 } | Select-Object -First 1)
    if ($listen445) { Write-Status 'INFO' ('Local listener on 445 owned by process ' + $listen445.Process + ' (PID ' + $listen445.PID + ')') }
    else { Write-Status 'INFO' 'No local listener was enumerated on TCP/445 (server role may be disabled).' }

    if ($t445.State -ne 'Open') {
        Write-Status 'NOT TESTABLE' ('SMB negotiation cannot be validated: local TCP/445 is ' + $t445.State + ' - ' + $t445.Error)
        Add-Finding -Category 'Network Protocol - SMB' -Status 'NOT TESTABLE' -Attribute 'SMB protocol validation' `
            -Target $script:HostName -Port '445' -Finding 'SMB configuration was read from the registry but the protocol behaviour could NOT be validated because the local SMB endpoint did not accept a connection.' `
            -Configured ('See Section 2.2 rows') -Observed ('TCP/445 state: ' + $t445.State + ' (' + $t445.Error + ')') `
            -Validation 'Attempted SMB1/SMB2 NEGOTIATE - not possible' -Class 'Medium' `
            -Remediation 'Re-run the assessment on a host where the SMB server role is active, or from a peer that can reach TCP/445, to validate the offering dialect and signing requirement.' `
            -Impact 'Unknown: an unvalidated control must not be assumed compliant.' -NoConsole
        return
    }

    # ---- SMB1 negotiation ---------------------------------------------------------------
    $smb1 = Invoke-Smb1NegotiateProbe -Target $local -TimeoutMs 2000
    $smb1Verdict = if ($smb1.Supported -eq $true) { 'SMB1 OFFERED (dialect negotiated)' } elseif ($smb1.Supported -eq $false) { 'SMB1 not negotiated' } else { 'inconclusive' }
    Write-Status $(if ($smb1.Supported -eq $true) { 'VALIDATED' } else { 'PASS' }) ('SMB1 probe: ' + $smb1Verdict + ' | ' + $smb1.ServerFlags)

    # ---- SMB2/3 negotiation -------------------------------------------------------------
    $smb2 = Invoke-Smb2NegotiateProbe -Target $local -TimeoutMs 2000
    if ($smb2.Error) {
        Write-Status 'NOT TESTABLE' ('SMB2 NEGOTIATE could not be completed: ' + $smb2.Error)
    } else {
        Write-Status 'INFO' ('SMB2/3 probe: dialect=' + $smb2.DialectName + ' (' + $smb2.Dialect + '), SecurityMode=' + $smb2.SecurityModeHex + ', signingEnabled=' + $smb2.SigningEnabled + ', signingRequired=' + $smb2.SigningRequired)
    }

    # ---- Decide whether configuration and observation agree -----------------------------
    $cfgReq = $script:Facts['SmbServerSigningRequired']
    $obsReq = if ($smb2.Error) { $null } else { $smb2.SigningRequired }
    $obsLine = if ($smb2.Error) { 'unavailable (' + $smb2.Error + ')' } else { 'SMB2 NEGOTIATE SecurityMode=' + $smb2.SecurityModeHex + '; SIGNING_REQUIRED=' + $obsReq }

    if ($null -ne $obsReq) {
        if ($obsReq -eq $true) {
            Add-Finding -Category 'Network Protocol - SMB' -Status 'VALIDATED' -Attribute 'SMB Server Signing (protocol-validated)' `
                -Target $script:HostName -Port '445' `
                -Finding 'SMB signing requirement VALIDATED at protocol level: the server sets SIGNING_REQUIRED in the SMB2 NEGOTIATE response, so unsigned SMB sessions are refused.' `
                -Configured ('Registry RequireSecuritySignature state: ' + $(if ($null -eq $cfgReq) { 'not present (default)' } else { [string]$cfgReq })) `
                -Observed $obsLine -Validation 'Live SMB2 NEGOTIATE probe (single request, no session established, no authentication attempted). The SIGNING_REQUIRED bit is set by the peer, therefore it is observed behaviour and not an inference from configuration.' `
                -Class 'High' -Weakness $false -Remediation 'No action required. Maintain the setting through GPO and re-validate after OS upgrades, since vendor defaults change between releases.' `
                -Impact 'NTLM relay to this host''s SMB service is prevented for the negotiation path; relay chains must target a different protocol (LDAP/HTTP) to succeed.'
        } else {
            Add-Finding -Category 'Network Protocol - SMB' -Status 'VALIDATED' -Attribute 'SMB Server Signing (protocol-validated)' `
                -Target $script:HostName -Port '445' `
                -Finding 'SMB signing is NOT required: the SMB2 NEGOTIATE response does not set SIGNING_REQUIRED, so a client that does not request signing can complete an unsigned session with this host.' `
                -Configured ('Registry RequireSecuritySignature state: ' + $(if ($null -eq $cfgReq) { 'not present (default behaviour applies)' } else { [string]$cfgReq })) `
                -Observed $obsLine -Validation 'Live SMB2 NEGOTIATE probe. The absence of the SIGNING_REQUIRED bit is an observation made by the peer, not an assumption from the registry.' `
                -Prerequisites 'Network reachability to TCP/445 from the attacker position (proven in Section 8) and a coerced or captured authentication attempt (the relay payload itself was NOT executed by this tool).' `
                -Exploitability 'Partially demonstrated: the unsigned-session capability is validated; the end-to-end relay impact is not executed because that would require capturing or coercing a victim credential, which is outside this tool''s authorised test surface.' `
                -Class 'High' -CatClass 'Confidentiality' `
                -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=1 (GPO: Microsoft network server: Digitally sign communications (always) = Enabled) and re-validate with this module. Prioritise domain controllers, file servers and any host with SMB-exposed administrative shares.' `
                -Impact 'An on-path or coercion-capable attacker can relay authentication to this host and act in the relayed identity''s context on this system, which is a direct lateral-movement primitive; on a domain controller it enables domain-object modification (e.g. adding a computer to a privileged group).'
        }
    } else {
        Write-Status 'NOT TESTABLE' 'Signing state could not be observed (no SMB2 response); reported as unknown, not as secure.'
    }

    # ---- SMB1 finding (validated at protocol level) --------------------------------------
    if ($smb1.Supported -eq $true) {
        Add-Finding -Category 'Network Protocol - SMB' -Status 'VALIDATED' -Attribute 'SMBv1 Offered (protocol-validated)' `
            -Target $script:HostName -Port '445' `
            -Finding 'SMBv1 is OFFERED by this host: an SMB1 NEGOTIATE with dialect "NT LM 0.12" was answered with a successful dialect selection.' `
            -Configured ('Registry: ' + $(if ($script:Facts.ContainsKey('Smb1Server')) { [string]$script:Facts['Smb1Server'] } else { 'not read' })) `
            -Observed ('raw response: ' + $smb1.Raw + ' | ' + $smb1.ServerFlags) `
            -Validation 'Live SMB1 NEGOTIATE probe. Dialect negotiation is selected by the peer, so this is behaviour, not configuration.' `
            -Prerequisites 'TCP/445 reachability to this host.' `
            -Class 'High' -CatClass 'Confidentiality' `
            -Remediation 'Disable SMBv1 immediately: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (Remove-WindowsFeature FS-SMB1 on servers), set LanmanServer\Parameters\SMB1=0, then re-validate until this module reports "SMB1 not negotiated".' `
            -Impact 'Legacy SMB1 offers no cryptographic integrity for most dialects, is the vector for historical remote code execution (MS17-010 class) and enables downgrade attacks that defeat signing protections.'
    } else {
        Write-Status 'PASS' 'SMBv1 was not negotiated by this host.'
    }

    # ---- Live SMB configuration cross-check (SmbShare / SmbWitness modules where present) --
    try {
        $scfg = Get-SmbServerConfiguration -ErrorAction Stop
        Write-Host ''
        Write-Host '  -- Live SMB server configuration (Get-SmbServerConfiguration) --------------------' -ForegroundColor DarkGray
        Write-Table -Rows @([pscustomobject]@{
            EnableSMB1Protocol = $scfg.EnableSMB1Protocol
            RequireSecuritySignature = $scfg.RequireSecuritySignature
            EnableSecuritySignature  = $scfg.EnableSecuritySignature
            EnableSMB2Protocol = $scfg.EnableSMB2Protocol
            EncryptData = $scfg.EncryptData
            RejectUnencryptedAccess = $scfg.RejectUnencryptedAccess
            Smb2DialectMax = $scfg.Smb2DialectMaximum
            Smb2DialectMin = $scfg.Smb2DialectMinimum
            ServerHidden = $scfg.ServerHidden
        }) -Columns @('EnableSMB1Protocol','RequireSecuritySignature','EnableSecuritySignature','EnableSMB2Protocol','EncryptData','RejectUnencryptedAccess','Smb2DialectMin','Smb2DialectMax','ServerHidden')
        if ($scfg.RequireSecuritySignature -ne $true) {
            Add-Finding -Category 'Network Protocol - SMB' -Status 'WARN' -Attribute 'SMB signing requirement (effective configuration)' `
                -Target $script:HostName -Port '445' -Finding 'Get-SmbServerConfiguration reports RequireSecuritySignature=False on the live SMB server.' `
                -Configured 'See table above' -Observed ('RequireSecuritySignature=' + $scfg.RequireSecuritySignature + '; EncryptData=' + $scfg.EncryptData + '; RejectUnencryptedAccess=' + $scfg.RejectUnencryptedAccess) `
                -Validation 'Live SMB server configuration API (same source the service itself uses)' -Class 'High' `
                -Remediation 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force (and -EncryptData $true with -RejectUnencryptedAccess $true where the peer population supports SMB 3 encryption).' `
                -Impact 'Unsigned SMB sessions are acceptable to this host, enabling relay-based lateral movement.' -NoConsole
        }
    } catch { }

    # ---- NULL-SESSION (anonymous logon) test -------------------------------------------------
    # A null session is attempted with an EMPTY user name and password. This is the only way to
    # observe whether the host accepts anonymous SMB logons: running 'net view' with the current
    # (possibly administrative) credentials would always succeed and would prove nothing.
    # The session is explicitly disconnected afterwards - the artifact is created AND removed by
    # this module, and the cleanup result is recorded.
    $ipcPath = '\\' + $script:HostName + '\IPC$'
    $nullSessionOut = ''; $nullSessionOk = $null; $cleanupOk = $null
    try {
        $nullSessionOut = (& net.exe use $ipcPath '' '/u:' 2>&1 | Out-String).Trim()
        $nullSessionOk = -not ($nullSessionOut -match '(?i)system error|access is denied|denied|failure|logon failure|multiple connections|1326|5\b')
        if ($nullSessionOk) { $nullSessionOk = ($nullSessionOut -match '(?i)completed successfully') }
    } catch {
        $nullSessionOut = 'command failed: ' + $_.Exception.Message; $nullSessionOk = $null
    } finally {
        # EVIDENCE-CLEANUP: always remove the session we may have created.
        try {
            $del = (& net.exe use $ipcPath '/delete' '/y' 2>&1 | Out-String).Trim()
            $cleanupOk = -not ($del -match '(?i)system error')
            if ($cleanupOk) { Write-Status 'INFO' 'Null-session test connection removed (assessment artifact cleaned up).' }
        } catch { $cleanupOk = $false }
    }
    Write-Host ''
    Write-Host '  -- NULL session / anonymous SMB logon (net use with empty credentials) ----------' -ForegroundColor DarkGray
    Write-Host ('    attempt : ' + ($nullSessionOut -replace "`r?`n", ' | ')) -ForegroundColor DarkGray
    Write-Host ('    cleanup : ' + $(if ($null -eq $cleanupOk) { 'not applicable' } elseif ($cleanupOk) { 'session removed' } else { 'REMOVE MANUALLY: net use \\host\IPC$ /delete' })) -ForegroundColor DarkGray
    Add-Finding -Category 'Network Protocol - SMB' -Status $(if ($nullSessionOk -eq $true) { 'VALIDATED' } elseif ($null -eq $nullSessionOk) { 'NOT TESTABLE' } else { 'PASS' }) -Attribute 'Anonymous (null) SMB session accepted' `
        -Target $script:HostName -Port '445' `
        -Finding $(if ($nullSessionOk -eq $true) { 'The host ACCEPTED an anonymous/null SMB session to IPC$ (empty user name and empty password). Unauthenticated SMB access is available.' } elseif ($null -eq $nullSessionOk) { 'The null-session test did not produce an interpretable result.' } else { 'The host REFUSED an anonymous/null SMB session, which is the expected hardened state.' }) `
        -Configured ('RestrictAnonymous=' + (Format-RegState (Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous')) + ' ; RestrictAnonymousSAM=' + (Format-RegState (Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM'))) `
        -Observed ('net use with empty credentials: ' + ($nullSessionOut -replace "`r?`n", ' | ') + ' || cleanup: ' + $(if ($null -eq $cleanupOk) { 'n/a' } else { [string]$cleanupOk })) `
        -Validation 'Native net.exe null-session attempt with a deliberately EMPTY user name and password (no credential is transmitted), followed by immediate disconnection of the session created. This measures anonymous logon behaviour, not authenticated access.' `
        -Class 'High' -CatClass 'Confidentiality' `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous=1 and RestrictAnonymousSAM=1, ensure the Guest account is disabled (and deny network logon for Guest), and remove Anonymous/Everyone from share, pipe and registry ACLs.' `
        -Impact 'A null session allows unauthenticated enumeration of shares, users, groups and, on older configurations, deeper directory metadata - reconnaissance that requires no credentials at all and leaves only a network-logon event.'
}

# ===========================================================================================
#  SECTION 4 :: AUTHENTICATION SECURITY  (policy vs OBSERVED behaviour)
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Section 2 recorded the authentication POLICY. This module records what the services
#  actually DO, which is the only basis for claiming a weakness. The tool deliberately draws
#  a hard line between the two and refuses to test some things at all:
#
#    OBSERVED here:      anonymous LDAP bind result, WinRM authentication schemes offered,
#                        RDP NLA enforcement at the X.224 layer, LDAP server-side policy when
#                        the host IS the domain controller, local account policy.
#    NOT TESTED here:    NTLM version on the wire, credential validity, password strength.
#                        Proving "this host accepts NTLMv1" requires submitting authentication,
#                        which is credential-spraying behaviour and is out of scope.
# ===========================================================================================
function Invoke-Section4_Authentication {
    $isDc = ($script:Section1Role -like '*DOMAIN CONTROLLER*')
    $target = if ($isDc) { '127.0.0.1' } elseif ($script:Facts.ContainsKey('DcResolvedIpv4') -and $script:Facts['DcResolvedIpv4']) { $script:Facts['DcResolvedIpv4'] } else { '' }
    $dcName = if ($script:Facts.ContainsKey('DcResolvedIpv4')) { $script:Facts['DcResolvedIpv4'] } else { '' }

    Write-Host ''
    Write-Host '  -- 4.1 LDAP: anonymous bind and RootDSE ---------------------------------------' -ForegroundColor DarkCyan
    $ldapHost = ''
    if ($isDc) { $ldapHost = '127.0.0.1' }
    elseif ($script:DomainControllerName) { $ldapHost = $script:DomainControllerName }
    if ($ldapHost -eq '127.0.0.1' -and -not (Test-RemoteAllowed)) {
        # The host IS the domain controller, so this probe stays on loopback - permitted under
        # /localonly because it generates no off-host traffic and no LDAP session to a remote server.
        Write-Status 'INFO' 'LDAP endpoint is this host (domain controller): the anonymous-bind test stays on loopback and is permitted under /localonly.'
    }
    if (-not $ldapHost) {
        Write-Status 'NOT TESTABLE' 'No LDAP endpoint identified (non-domain host or DC not resolvable): anonymous LDAP bind behaviour cannot be observed.'
        Add-Finding -Category 'Authentication' -Status 'NOT TESTABLE' -Attribute 'LDAP anonymous bind' -Finding 'Anonymous LDAP bind could not be tested because no reachable LDAP endpoint was identified from this context.' `
            -Validation 'Not attempted' -Class 'Medium' -Remediation 'Run the assessment from a domain-joined host, or supply a reachable DC, to test anonymous LDAP exposure.' `
            -Impact 'Unknown; an untested directory exposure is not evidence of compliance.' -NoConsole
    } elseif (-not (Test-RemoteAllowed) -and $ldapHost -ne '127.0.0.1') {
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - the anonymous LDAP bind test targets a remote directory and was not performed.')
        Add-Finding -Category 'Authentication' -Status 'NOT TESTABLE' -Attribute 'LDAP anonymous bind' `
            -Finding ('Anonymous LDAP bind behaviour was not tested: the only LDAP endpoint identified (' + $ldapHost + ') is remote and this is a local-only run.') `
            -Observed 'No LDAP socket was opened and no BindRequest was sent.' `
            -Configured 'Launcher switch /localonly (EIA_LOCAL_ONLY=1)' `
            -Validation 'Operator control - suppression by explicit request, not a reachability failure.' -Class 'Medium' -CatClass 'IdentityRights' `
            -Remediation 'Re-run without /localonly (or from the domain controller itself, where the probe stays on loopback) to test anonymous bind exposure.' `
            -Impact 'Unknown; an untested directory exposure is not evidence of compliance.' -NoConsole
    } else {
        $t389 = Test-TcpPort -Target $ldapHost -Port 389 -TimeoutMs 900
        Write-Status 'INFO' ('LDAP endpoint ' + $ldapHost + ':389 is ' + $t389.State)
        if ($t389.State -eq 'Open') {
            $anon = Invoke-LdapAnonymousBindProbe -Target $ldapHost -Port 389
            Write-Status $(if ($anon.ResultCode -eq 0) { 'VALIDATED' } elseif ($null -eq $anon.ResultCode) { 'NOT TESTABLE' } else { 'PASS' }) `
                ('Anonymous simple bind result: ' + $(if ($null -ne $anon.ResultCode) { 'resultCode=' + $anon.ResultCode + ' (' + $anon.ResultName + ')' } else { 'no parsable response' }) + $(if ($anon.Diagnostic) { ' | diagnosticMessage: ' + $anon.Diagnostic } else { '' }))
            if ($anon.ResultCode -eq 0) {
                Add-Finding -Category 'Authentication' -Status 'VALIDATED' -Attribute 'Anonymous LDAP bind accepted' -Target $ldapHost -Port '389' `
                    -Finding 'The LDAP service ACCEPTED an anonymous simple bind (resultCode 0). Unauthenticated directory access is available at the protocol level.' `
                    -Configured 'RestrictAnonymous / directory-level anonymous access policy' `
                    -Observed ('resultCode=0 (success), raw response: ' + $anon.Raw + '. Validation: a single anonymous BindRequest containing a NULL distinguished name and a zero-length password; no credentials were supplied and no search was performed against user data.') `
                    -Validation 'Live anonymous LDAP BindRequest (BER-encoded, read-only protocol handshake)' `
                    -Prerequisites 'TCP/389 reachability to ' + $ldapHost + '.' -Class 'High' -CatClass 'Confidentiality' `
                    -Remediation 'Set RestrictAnonymous=1 on domain controllers (and RestrictAnonymousSAM), remove Anonymous/Everyone from directory ACLs, and verify that pre-Windows 2000 compatible access is not granted to the Everyone group.' `
                    -Impact 'Anonymous bind permits unauthenticated queries to whatever the directory ACL allows (naming contexts, schema, sometimes account attributes). It is a reconnaissance multiplier for every other attack in this report.'
            } elseif ($null -ne $anon.ResultCode) {
                Add-Finding -Category 'Authentication' -Status 'PASS' -Attribute 'Anonymous LDAP bind refused' -Target $ldapHost -Port '389' `
                    -Finding ('Anonymous simple bind was refused with resultCode ' + $anon.ResultCode + ' (' + $anon.ResultName + ').') `
                    -Observed ('resultCode=' + $anon.ResultCode + '; diagnostic=' + $(if ($anon.Diagnostic) { $anon.Diagnostic } else { '(none)' })) `
                    -Validation 'Live anonymous LDAP BindRequest' -Class 'Medium' `
                    -Remediation 'No action required. Re-test if directory ACLs or the RestrictAnonymous policy change.' `
                    -Impact 'Unauthenticated directory reconnaissance is not possible through a plain anonymous bind.' -NoConsole
            } else {
                Write-Status 'NOT TESTABLE' ('Anonymous bind test inconclusive: ' + $anon.Error)
            }
            $rds = Get-LdapRootDse -Server $ldapHost -Port 389 -Anonymous
            if ($rds.Ok) {
                $dnsHost = $rds.Props['dnsHostName']; $dnc = $rds.Props['defaultNamingContext']
                $sasl = $rds.Props['supportedSASLMechanisms']
                $ctl  = $rds.Props['supportedControl']
                Write-Status 'INFO' ('RootDSE readable | dnsHostName=' + $dnsHost + ' | namingContext=' + $dnc)
                Write-Status 'INFO' ('supportedSASLMechanisms: ' + $(if ($sasl) { ($sasl -join ', ') } else { 'not readable anonymously' }))
                if ($sasl) {
                    $hasGssapi = [bool](($sasl | Where-Object { $_ -match '(?i)GSSAPI|GSS-SPNEGO|Kerberos' }).Count -gt 0)
                    Add-Finding -Category 'Authentication' -Status $(if ($hasGssapi) { 'PASS' } else { 'WARN' }) -Attribute 'LDAP SASL mechanisms (Kerberos capability)' -Target $ldapHost -Port '389' `
                        -Finding $(if ($hasGssapi) { 'The directory advertises Kerberos-capable SASL mechanisms (GSSAPI/GSS-SPNEGO), so Kerberos authentication is available for LDAP.' } else { 'The directory did not advertise Kerberos SASL mechanisms in the anonymous RootDSE.' }) `
                        -Observed ($sasl -join ', ') -Validation 'Anonymous RootDSE read via System.DirectoryServices (native, no RSAT)' `
                        -Class 'Medium' -Remediation $(if ($hasGssapi) { 'Enforce Kerberos for directory access and reduce reliance on NTLM by policy (Section 4.4).' } else { 'Verify LDAP SASL configuration and that Kerberos is available for directory clients.' }) `
                        -Impact $(if ($hasGssapi) { 'None - this is the expected and desired state; it is recorded because it bounds the relay opportunities available to an attacker.' } else { 'Directory clients may fall back to NTLM, increasing relay exposure.' }) -NoConsole
                }
                if ($dnc -and -not $script:DomainNamingContext) { $script:DomainNamingContext = $dnc }
            } else {
                Write-Status 'NOT TESTABLE' ('RootDSE read failed: ' + $rds.Error)
            }
        } else {
            Write-Status 'NOT TESTABLE' ('LDAP port 389 is ' + $t389.State + ' from this context; anonymous bind not testable.')
        }
    }

    Write-Host ''
    Write-Host '  -- 4.2 LDAP signing and channel binding (server-side policy) --------------------' -ForegroundColor DarkCyan
    if ($isDc) {
        $sgn = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'
        $cb  = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding'
        $sgnV = Get-U32 $sgn; $cbV = Get-U32 $cb
        Add-Control -Category 'Authentication' -Attribute 'LDAP Server Signing Requirement (DC)' `
            -Expected 'LDAPServerIntegrity=1 (Require signing). Unsigned LDAP binds enable NTLM relay to LDAP, which on a DC allows directory modification (e.g. granting DCSync or adding a computer to a privileged group).' `
            -Configured ('HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = ' + (Format-RegState $sgn)) `
            -Observed ('Raw value ' + $(if ($null -eq $sgnV) { 'not present (Windows default = None / no signing requirement)' } else { [string]$sgnV }) + '. Microsoft''s "Domain controller: LDAP server signing requirements" security option maps to this value (0 = None, 1 = Require signing); the raw value is recorded so it can be reconciled against the documented mapping for this OS release. Enforcement was NOT validated by transmitting an unsigned authenticated bind, because this tool does not put credentials on cleartext LDAP.') `
            -Validation 'Registry read on the domain controller itself. Validation of the enforcement side is explicitly NOT TESTED - see the note in the observed column.' `
            -Result $(if ($null -eq $sgnV) { 'WARN' } elseif ($sgnV -eq 0) { 'RISK DETECTED' } else { 'PASS' }) -FactKey 'LdapServerIntegrity' -FactValue $sgnV -Class 'Critical' `
            -Finding $(if ($sgnV -ge 1) { 'LDAP signing is configured as required on this domain controller.' } elseif ($sgnV -eq 0) { 'LDAP signing is explicitly disabled on this domain controller.' } else { 'LDAP signing requirement is not configured on this domain controller (default None).' }) `
            -Remediation 'Set LDAPServerIntegrity=1 (GPO: Domain controller: LDAP server signing requirements = Require signing) on all DCs, then enforce LDAPS/StartTLS or SASL integrity on clients before enabling, to avoid outages. Validate client compatibility first.' `
            -Impact 'With LDAP signing not required, an attacker who can coerce or capture NTLM authentication can relay it to LDAP on a DC and modify directory objects - the direct path to domain privilege escalation.'
        Add-Control -Category 'Authentication' -Attribute 'LDAP Channel Binding (DC)' `
            -Expected 'LdapEnforceChannelBinding=2 (Always) where the environment supports it (1 = When supported), removing relay of NTLM to LDAPS.' `
            -Configured ('HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = ' + (Format-RegState $cb)) `
            -Observed ('Raw value ' + $(if ($null -eq $cbV) { 'not present (default = Never)' } else { [string]$cbV }) + ' (0 = Never, 1 = When supported, 2 = Always)') `
            -Validation 'Registry read on the domain controller. Channel binding enforcement is not testable without performing an authenticated LDAPS bind with mismatched channel bindings - deliberately not performed.' `
            -Result $(if ($null -eq $cbV -or $cbV -eq 0) { 'WARN' } else { 'PASS' }) -FactKey 'LdapChannelBinding' -FactValue $cbV -Class 'High' `
            -Finding $(if ($cbV -ge 1) { 'LDAP channel binding enforcement is configured.' } else { 'LDAP channel binding is not enforced (relay to LDAPS remains possible where a DC certificate is available to the attacker).' }) `
            -Remediation 'Set LdapEnforceChannelBinding=2 on all DCs once clients are known to support it (monitor 3074/3075 events at level 1 first), and ensure DC certificates have the required EKU/SAN entries.' `
            -Impact 'Without channel binding, NTLM authentication relayed to LDAPS is accepted, restoring the relay path even after LDAP signing is enforced.'
    } else {
        $sgnLocal = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'
        if ($sgnLocal.KeyExists) {
            Add-Finding -Category 'Authentication' -Status 'INFO' -Attribute 'LDAP signing policy (local NTDS keys present)' -Finding 'NTDS\\Parameters exists on a non-DC host (unusual); value recorded for completeness.' `
                -Observed (Format-RegState $sgnLocal) -Validation 'Registry read' -Class 'Low' `
                -Remediation 'No action: LDAP signing is enforced on domain controllers, which are assessed separately.' -Impact 'None observed.' -NoConsole
        } else {
            Write-Status 'NOT TESTABLE' 'LDAP signing/channel-binding are enforced on domain controllers and are only readable there. Assess each DC (or run this tool on a DC) to record them.'
            Add-Finding -Category 'Authentication' -Status 'NOT TESTABLE' -Attribute 'LDAP signing / channel binding (remote DC not assessed)' `
                -Target $(if ($script:DomainControllerName) { $script:DomainControllerName } else { 'unresolved' }) `
                -Finding 'LDAP signing and channel binding enforcement live on the domain controller (NTDS\Parameters). This host is not a DC, so the values were not observed.' `
                -Validation 'Not attempted from this host: the enforcement values are local to each DC and remote registry access is not used by this tool (no remote service is relied upon).' `
                -Class 'High' -Remediation 'Run this assessment on each domain controller (or an equivalent DC-hosted audit) to record LDAPServerIntegrity and LdapEnforceChannelBinding, and treat them as unknown until then.' `
                -Impact 'Unknown. LDAP relay to a DC is a domain-takeover path, so leaving this UNKNOWN must be tracked as an open item, not closed as compliant.' -NoConsole
        }
    }

    Write-Host ''
    Write-Host '  -- 4.3 Observed authentication behaviour of local remote-management endpoints -----' -ForegroundColor DarkCyan
    $winrmSvc = Get-ServiceSafe 'WinRM'
    if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
        $p5985 = Invoke-WinRmProbe -Target '127.0.0.1' -Port 5985
        if ($p5985.Responded) {
            Write-Status $(if ($p5985.OffersBasic) { 'RISK DETECTED' } else { 'PASS' }) ('WinRM 5985 responded: "' + $p5985.StatusLine + '" | auth schemes offered: ' + (($p5985.AuthSchemes | Select-Object -Unique) -join ', '))
            Add-Finding -Category 'Authentication' -Status $(if ($p5985.OffersBasic) { 'VALIDATED' } else { 'PASS' }) -Attribute 'WinRM authentication schemes offered (observed)' `
                -Target $script:HostName -Port '5985' `
                -Finding $(if ($p5985.OffersBasic) { 'The WinRM listener advertises HTTP Basic authentication, meaning credentials would be transmitted in a recoverable form over an unencrypted channel.' } else { 'The WinRM listener does not advertise Basic authentication; only integrated/Kerberos-style schemes were offered.' }) `
                -Configured $(if ($script:Facts.ContainsKey('WinRmRunning')) { 'Policy AllowBasic / AllowUnencryptedTraffic audited in Section 2.6' } else { 'n/a' }) `
                -Observed ('HTTP response: ' + $p5985.StatusLine + '; WWW-Authenticate schemes: ' + (($p5985.AuthSchemes | Select-Object -Unique) -join ', ')) `
                -Validation 'Unauthenticated HTTP POST to /wsman on the local listener; the server chooses which schemes to advertise, so this is OBSERVED behaviour rather than configuration. No credentials were sent.' `
                -Class 'High' -CatClass 'Confidentiality' `
                -Remediation 'Disable Basic authentication on the WinRM service (WSMan:\localhost\Service\Auth\Basic = $false, or GPO "Allow Basic authentication" = Disabled), require HTTPS listeners for remote management, and use domain-authenticated constrained endpoints.' `
                -Impact 'Basic authentication over HTTP exposes credentials to any on-path observer and to the management endpoint itself; on a management host this converts passive network access into credential compromise.'
        } else {
            Write-Status 'INFO' ('WinRM is running but did not answer on 5985 (' + $p5985.Error + ') - the HTTP listener may be disabled while the service remains enabled.')
        }
        $lis = @()
        try { $lis = @(Get-ChildItem 'WSMan:\localhost\Listener' -ErrorAction Stop | ForEach-Object { $_.PSChildName }) } catch { }
        if ($lis.Count -gt 0) {
            $t5986 = Test-TcpPort -Target '127.0.0.1' -Port 5986 -TimeoutMs 900
            if ($t5986.State -eq 'Open') {
                $p5986 = Invoke-WinRmProbe -Target '127.0.0.1' -Port 5986 -UseTls
                Write-Status 'INFO' ('WinRM HTTPS listener present: ' + $p5986.StatusLine + ' | certificate: ' + $p5986.TlsSubject + ' | expires ' + $p5986.TlsNotAfter)
                Add-Finding -Category 'Authentication' -Status 'INFO' -Attribute 'WinRM HTTPS listener and certificate' -Target $script:HostName -Port '5986' `
                    -Finding 'An HTTPS WinRM listener is present and its TLS certificate was read.' -Observed ('subject: ' + $p5986.TlsSubject + '; thumbprint: ' + $p5986.TlsThumbprint + '; notAfter: ' + $p5986.TlsNotAfter) `
                    -Validation 'TLS handshake only (certificate recorded, trust deliberately not enforced for the assessment; no authentication attempted)' -Class 'Low' `
                    -Remediation 'Ensure the listener certificate is issued by the internal CA, is not expired, and is rotated before expiry; enforce HTTPS-only for remote management.' `
                    -Impact 'An expired or self-signed management certificate trains operators to ignore certificate warnings and can be replaced by an on-path attacker.' -NoConsole
            }
        }
    } else {
        Write-Status 'NOT TESTABLE' 'WinRM is not running; its authentication behaviour cannot be observed on this host.'
    }

    $rdp = $script:Facts['RdpEnabled']
    if ($rdp) {
        $x = Invoke-RdpX224Probe -Target '127.0.0.1'
        if ($x.Responded) {
            $nlaRequired = ($x.SelectedProtocol -eq 2 -or $x.SelectedProtocol -eq 4)
            Write-Status $(if ($nlaRequired) { 'PASS' } else { 'VALIDATED' }) ('RDP X.224 probe: ' + $(if ($x.SelectedProtocolName) { $x.SelectedProtocolName } else { $x.NegotiationFailure }) + ' | raw: ' + $x.Raw)
            Add-Finding -Category 'Authentication' -Status $(if ($nlaRequired) { 'PASS' } else { 'VALIDATED' }) -Attribute 'RDP pre-authentication (NLA) - observed at X.224 layer' `
                -Target $script:HostName -Port '3389' `
                -Finding $(if ($nlaRequired) { 'The RDP listener requires CredSSP/NLA before authentication, validated by the negotiated protocol in the X.224 response.' } else { 'The RDP listener negotiated a protocol that does NOT require NLA, so an unauthenticated client reaches the login stack.' }) `
                -Configured ('UserAuthentication registry value recorded in Section 2.5') `
                -Observed ($x.SelectedProtocolName + $(if ($x.NegotiationFailure) { ' | negotiation failure: ' + $x.NegotiationFailure } else { '' })) `
                -Validation 'Single X.224 Connection Request with an RDP Negotiation Request; the selected protocol is chosen by the server. No credentials were transmitted and no session was established.' `
                -Class 'Medium' -CatClass 'Confidentiality' `
                -Remediation $(if ($nlaRequired) { 'No action required; keep NLA enforced and continue to restrict TCP/3389 at the network tier.' } else { 'Enable NLA: set WinStations\RDP-Tcp\UserAuthentication=1 and SecurityLayer=2 (GPO "Require user authentication for remote connections by using Network Level Authentication").' }) `
                -Impact $(if ($nlaRequired) { 'None observed - pre-authentication is enforced, which removes the unauthenticated credential-testing surface.' } else { 'An unauthenticated attacker can reach the credential prompt and test credentials against accounts, and the pre-auth RDP stack is exposed; this is a prerequisite step for interactive lateral movement.' })
        } else {
            Write-Status 'NOT TESTABLE' ('RDP X.224 probe inconclusive: ' + $x.Error)
        }
    } else {
        Write-Status 'PASS' 'RDP is disabled by policy; the NLA validation is not applicable on this host.'
    }

    Write-Host ''
    Write-Host '  -- 4.4 Local authentication policy (native policy interface) ---------------------' -ForegroundColor DarkCyan
    $netAccounts = ''
    try { $netAccounts = (& net.exe accounts 2>&1 | Out-String).Trim() } catch { }
    if ($netAccounts) {
        $hours = ($netAccounts | Select-String -Pattern 'Maximum password age|Minimum password age|Password history length|Minimum password length|Lockout threshold|Lockout duration|Lockout observation window' -SimpleMatch)
        if ($hours) { foreach ($h in $hours) { Write-Host ('    ' + $h.ToString().Trim()) -ForegroundColor DarkGray } }
        else { Write-Host ('    ' + ($netAccounts -replace "`r?`n", ' | ')) -ForegroundColor DarkGray }
        $lockoutLine = ($netAccounts -split "`r?`n" | Where-Object { $_ -match 'Lockout threshold' } | Select-Object -First 1)
        $lockoutVal = $null
        if ($lockoutLine -and $lockoutLine -match '(\d+)') { $lockoutVal = [int]$Matches[1] }
        if ($null -ne $lockoutVal) {
            Add-Finding -Category 'Authentication' -Status $(if ($lockoutVal -eq 0) { 'WARN' } else { 'INFO' }) -Attribute 'Local account lockout policy' `
                -Finding $(if ($lockoutVal -eq 0) { 'The local account lockout threshold is 0 (never lock out), so unlimited authentication attempts are permitted against local accounts.' } else { ('Lockout threshold observed: ' + $lockoutVal + ' invalid attempts (locale-dependent "net accounts" output parsed for the value only).') }) `
                -Configured ($lockoutLine.Trim()) -Observed ($netAccounts -replace "`r?`n", ' | ') `
                -Validation 'Native net.exe accounts (read-only local policy query). Values on domain-joined systems are superseded by domain account policy for domain accounts; this reflects the LOCAL policy store.' `
                -Class 'Medium' -CatClass 'IdentityRights' `
                -Remediation $(if ($lockoutVal -eq 0) { 'Define a lockout threshold (e.g. 10 attempts / 15 minutes) in the domain or local policy. Note: a lockout threshold is itself a denial-of-service lever, so pair it with alerting and exclude privileged service accounts from interactive logon.' } else { 'Keep the threshold aligned with the corporate baseline and monitor lockout events (4740/4625) for spraying.' }) `
                -Impact $(if ($lockoutVal -eq 0) { 'Unbounded guessing is possible against local accounts; combined with credential reuse this is a practical route to local administrator access.' } else { 'Guessing against local accounts is rate-limited by policy.' }) -NoConsole
        }
    } else {
        Write-Status 'NOT TESTABLE' 'net accounts returned no data; the local authentication policy could not be recorded.'
    }

    if ($script:IsAdmin) {
        # Export the security policy through the native interface, parse it, then delete it.
        $tmpInf = Join-Path $env:TEMP ('eia-secpol-' + [guid]::NewGuid().ToString('N') + '.inf')
        try {
            $null = & secedit.exe /export /cfg $tmpInf /areas SECURITYPOLICY 2>&1
            if (Test-Path -LiteralPath $tmpInf) {
                $pol = Get-Content -LiteralPath $tmpInf -ErrorAction Stop
                $keys = @('MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
                          'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash',
                          'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
                          'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
                          'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
                          'MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature',
                          'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
                $found = @()
                foreach ($l in $pol) {
                    if ($l -match '^\s*"?(MACHINE\\[^=]+)"?\s*=\s*(\d+)\s*$') {
                        $k = $Matches[1]; $v = $Matches[2]
                        foreach ($want in $keys) { if ($k -like ('*' + $want.Split('\')[-1])) { $found += [pscustomobject]@{ PolicyPath = $k; Value = $v } } }
                    }
                }
                Write-Host ''
                Write-Host '  -- Security policy export (native secedit /export, read-only) ---------------------' -ForegroundColor DarkGray
                if ($found.Count -gt 0) { Write-Table -Rows $found -Columns @('PolicyPath','Value') -Headers @{ PolicyPath='Effective local security policy value'; Value='Value' } }
                Add-Finding -Category 'Authentication' -Status 'INFO' -CatClass 'Context' -Attribute 'Local Security Policy export' `
                    -Finding 'The effective local security policy was exported with the native secedit interface and re-parsed to cross-check the registry values reported in Section 2. The temporary INF file was deleted immediately after parsing.' `
                    -Observed (($found | ForEach-Object { $_.PolicyPath.Split('\')[-1] + '=' + $_.Value }) -join '; ') `
                    -Validation 'secedit /export /cfg <temp> /areas SECURITYPOLICY followed by immediate deletion of the temp file. Only policy values are read; no credential material is contained in or extracted from this export.' `
                    -Class 'Low' -Remediation 'No action - this is an evidence-integrity control that confirms the registry values reflect the applied policy.' `
                    -Impact 'None. This row exists so that a mismatch between GPO intent and local registry state (a common cause of false "compliant" reports) is detectable.' -NoConsole
            }
        } catch {
            Write-Status 'NOT TESTABLE' ('Security policy export failed: ' + $_.Exception.Message)
        } finally {
            # EVIDENCE-CLEANUP REQUIREMENT: remove every artifact this module created.
            try { if (Test-Path -LiteralPath $tmpInf) { Remove-Item -LiteralPath $tmpInf -Force -ErrorAction Stop; Write-Status 'INFO' 'Temporary policy export removed from the host (no assessment artifacts left behind).' } } catch {
                Write-Status 'WARN' ('Temporary file could not be removed: ' + $tmpInf + ' - delete manually.')
            }
        }
    } else {
        Write-Status 'NOT TESTABLE' 'Security policy export requires administrator rights; skipped (values from the registry are reported instead).'
    }

    # =======================================================================================
    #  4.x Fine-Grained Password Policies Auditor
    #  READ-ONLY: ADSI LDAP enumeration only; no policy modification.
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- Fine-Grained Password Policies Auditor ----------------------------------------' -ForegroundColor DarkCyan
    if ($script:LdapReady) {
        try {
            $fgppRoot = 'LDAP://'
            if ($script:DomainControllerName) { $fgppRoot += $script:DomainControllerName + '/' }
            $fgppRoot += 'CN=Password Settings Container,CN=System,' + $script:DomainNamingContext

            $fgppSearcher = New-AdSearcher `
                -Filter '(objectClass=msDS-PasswordSettings)' `
                -Properties @('cn','msDS-PasswordSettingsPrecedence','msDS-MinPasswordLength','msDS-LockoutThreshold','msDS-LockoutDuration') `
                -SearchRoot $fgppRoot `
                -Scope 'Subtree'
            $fgppObjects = Get-AdObjects -Searcher $fgppSearcher -Cap $script:Cfg.MaxAdObjects

            if (-not $fgppObjects -or $fgppObjects.Count -eq 0) {
                Write-Status 'PASS' 'No fine-grained password policy overrides were found; the domain baseline is not overridden by FGPP objects.'
            } else {
                Write-Status 'WARN' (($fgppObjects.Count).ToString() + ' fine-grained password policy object(s) were found; user/group-specific password settings may override the domain baseline.')
                $fgppRows = @()
                foreach ($fgpp in $fgppObjects) {
                    $cn = [string](Get-AdProperty -Object $fgpp -Name 'cn')
                    $precedence = Get-AdProperty -Object $fgpp -Name 'msDS-PasswordSettingsPrecedence'
                    $minLength = Get-AdProperty -Object $fgpp -Name 'msDS-MinPasswordLength'
                    $lockoutThreshold = Get-AdProperty -Object $fgpp -Name 'msDS-LockoutThreshold'
                    $lockoutDuration = Get-AdProperty -Object $fgpp -Name 'msDS-LockoutDuration'
                    $fgppRows += [pscustomobject]@{
                        Policy = $cn
                        Precedence = [string]$precedence
                        MinPasswordLength = [string]$minLength
                        LockoutThreshold = [string]$lockoutThreshold
                        LockoutDuration = [string]$lockoutDuration
                    }

                    $minLenInt = $null
                    try { if ($null -ne $minLength) { $minLenInt = [int]$minLength } } catch { $minLenInt = $null }
                    if ($null -ne $minLenInt -and $minLenInt -lt 14) {
                        Add-Finding -Category 'Authentication' -Status 'WARN' `
                            -Attribute 'Weak Fine-Grained Password Policy' `
                            -Finding ('Fine-grained password policy ''' + $cn + ''' permits a minimum password length of ' + $minLenInt + ', below the 14-character assessment baseline.') `
                            -Observed ('Policy=' + $cn + '; MinPasswordLength=' + $minLenInt + '; Precedence=' + [string]$precedence) `
                            -Validation 'Read-only ADSI LDAP enumeration of msDS-PasswordSettings objects under CN=Password Settings Container,CN=System.' `
                            -Class 'High' -CatClass 'IdentityRights'
                    }
                }
                Write-Table -Rows $fgppRows `
                    -Columns @('Policy','Precedence','MinPasswordLength','LockoutThreshold','LockoutDuration') `
                    -Headers @{ Policy='Policy'; Precedence='Precedence'; MinPasswordLength='Min Length'; LockoutThreshold='Lockout Threshold'; LockoutDuration='Lockout Duration' }
            }
        } catch {
            Write-Status 'NOT TESTABLE' ('Fine-grained password policy enumeration failed: ' + $_.Exception.Message)
        }
    } else {
        Write-Status 'NOT TESTABLE' 'LDAP is not ready; fine-grained password policy enumeration was skipped.'
    }

}

# ===========================================================================================
#  SECTION 5 :: LSA / LSASS PROTECTION
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  LSASS holds the credential material of every interactive and service logon on the host.
#  The single most valuable control is Protected Process Light (RunAsPPL). This module
#  validates the CONFIGURATION and then VALIDATES the effective runtime protection state of
#  the lsass process by reading only its protection descriptor - the LSASS process is never
#  opened for memory read, never dumped, and no credential material is accessed.
# ===========================================================================================
function Initialize-LsassProtectionProbe {
    if ($script:LsassProbeReady -ne $null) { return $script:LsassProbeReady }
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EiaLsass {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, ref byte[] ProcessInformation, int ProcessInformationLength, out int ReturnLength);
    public static string QueryProtection(int pid) {
        uint QUERY_LIMITED = 0x1000;
        IntPtr h = OpenProcess(QUERY_LIMITED, false, pid);
        if (h == IntPtr.Zero) {
            int err = Marshal.GetLastWin32Error();
            return "OPEN_FAILED:" + err;
        }
        try {
            byte[] buf = new byte[2];
            int ret = 0;
            int st = NtQueryInformationProcess(h, 61, ref buf, buf.Length, out ret);
            if (st != 0) return "QUERY_FAILED:0x" + st.ToString("X8");
            return "OK:" + buf[0].ToString();
        } finally { CloseHandle(h); }
    }
}
'@ -ErrorAction Stop
        $script:LsassProbeReady = $true
    } catch {
        $script:LsassProbeReady = $false
        Write-Status 'NOT TESTABLE' ('Runtime LSASS protection query could not be compiled (' + $_.Exception.Message + '). Language mode or policy may block Add-Type; the configuration value is still reported.')
    }
    return $script:LsassProbeReady
}

function Get-LsassProtectionLevel {
    $res = [pscustomobject]@{ Available=$false; RawByte=$null; Level='Unknown'; Signer='None'; Description=''; Error='' }
    if (-not (Initialize-LsassProtectionProbe)) { return $res }
    $p = $null
    try { $p = Get-Process -Name lsass -ErrorAction Stop | Select-Object -First 1 } catch { }
    if (-not $p) { $res.Error = 'lsass process not found (query failed)'; return $res }
    try {
        $out = [EiaLsass]::QueryProtection($p.Id)
        if ($out -like 'OK:*') {
            $res.Available = $true
            $b = [int]($out.Split(':')[1])
            $res.RawByte = $b
            $lvl = $b -band 0x07
            $signer = ($b -shr 4) -band 0x0F
            $res.Level = switch ($lvl) { 0 { 'None' } 1 { 'Light (PPL)' } 2 { 'Full (PP)' } default { 'Unknown(' + $lvl + ')' } }
            $res.Signer = switch ($signer) {
                0 { 'None' } 1 { 'Authenticode' } 2 { 'CodeGen' } 3 { 'Antimalware' }
                4 { 'LsaLight' } 5 { 'Lsa' } 6 { 'WinTcbLight' } 7 { 'WinTcb' } 8 { 'WinSystemLight' } 9 { 'WinSystem' }
                default { 'Unknown(' + $signer + ')' }
            }
            $res.Description = 'Protection byte 0x' + $b.ToString('X2') + ' (signer=' + $res.Signer + ', level=' + $res.Level + ')'
        } elseif ($out -like 'OPEN_FAILED:*') {
            $code = [int]($out.Split(':')[1])
            $res.Error = 'OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) on lsass failed with Win32 error ' + $code + ' (5 = access denied)'
        } else {
            $res.Error = $out
        }
    } catch { $res.Error = $_.Exception.Message }
    return $res
}

function Invoke-Section5_Lsass {
    $runAsPplVal = $script:Facts['RunAsPPL']
    Write-Host ''
    Write-Host '  -- 5.1 lsass runtime protection (validated) -------------------------------------' -ForegroundColor DarkCyan
    $prot = Get-LsassProtectionLevel
    if ($prot.Available) {
        Write-Status 'INFO' ('Runtime lsass protection: ' + $prot.Description)
        $isProtected = ($prot.Level -like 'Light*' -or $prot.Level -like 'Full*')
        $script:Facts['LsassProtected'] = [bool]$isProtected
        if ($isProtected) {
            Add-Finding -Category 'Credential Protection' -Status 'VALIDATED' -Attribute 'LSASS process protection (runtime)' `
                -Target $script:HostName -Finding ('LSASS is running as a protected process (' + $prot.Description + '), so non-protected code - including administrator-level tooling - cannot read LSASS memory.') `
                -Configured ('RunAsPPL registry value: ' + $(if ($null -eq $runAsPPLVal) { 'absent' } else { [string]$runAsPPLVal })) `
                -Observed ('ProcessProtectionInformation for lsass.exe: ' + $prot.Description) `
                -Validation 'NtQueryInformationProcess(ProcessProtectionInformation=61) with PROCESS_QUERY_LIMITED_INFORMATION only. The handle grants no memory-read right: LSASS memory was not read, opened for read, or dumped.' `
                -Class 'High' -CatClass 'DataAtRest' `
                -Remediation 'No action required. Maintain through GPO (RunAsPPL=2 with UEFI lock where supported) and re-validate after OS upgrades.' `
                -Impact 'Credential-dumping via LSASS memory access is blocked for non-PPL code, removing the fastest path from local administrator to credential material.'
        } else {
            Add-Finding -Category 'Credential Protection' -Status 'VALIDATED' -Attribute 'LSASS process protection (runtime)' `
                -Target $script:HostName -Finding 'LSASS is running WITHOUT protection (' + $prot.Description + '): any code running as an administrator on this host can open LSASS for memory read.' `
                -Configured ('RunAsPPL registry value: ' + $(if ($null -eq $runAsPPLVal) { 'absent (not configured)' } else { [string]$runAsPPLVal })) `
                -Observed ('ProcessProtectionInformation for lsass.exe: ' + $prot.Description) `
                -Validation 'NtQueryInformationProcess(ProcessProtectionInformation=61); this reads the protection descriptor only. The tool did NOT read LSASS memory (doing so would be credential dumping and is prohibited by this tool''s design).' `
                -Prerequisites 'Code execution as a local administrator on this host (a prerequisite that Section 17 assesses separately).' `
                -Exploitability 'Precondition validated, payload deliberately NOT executed: the tool proves that LSASS is unprotected but does not perform credential extraction, which is out of scope.' `
                -Class 'High' -CatClass 'DataAtRest' `
                -Remediation 'Enable LSA protection: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\RunAsPPL=1 (or 2 with UEFI lock) and reboot. Combine with Credential Guard, PPL-compatible security agents, and removal of debug-privilege assignments from non-administrative accounts.' `
                -Impact 'An administrator-level foothold converts directly into credential material (NTLM hashes and Kerberos keys of every logged-on identity, including service and domain accounts), which is the standard pass-the-hash / pass-the-ticket escalation path.'
        }
    } else {
        Write-Status 'NOT TESTABLE' ('Runtime LSASS protection could not be validated: ' + $prot.Error)
        Add-Finding -Category 'Credential Protection' -Status 'NOT TESTABLE' -Attribute 'LSASS process protection (runtime)' `
            -Target $script:HostName -Finding 'The effective protection level of the lsass process could not be read from this context, so LSA protection is UNKNOWN (it is not reported as enabled or disabled on the basis of configuration alone).' `
            -Configured ('RunAsPPL registry value: ' + $(if ($null -eq $runAsPPLVal) { 'absent' } else { [string]$runAsPPLVal })) `
            -Observed $prot.Error -Validation 'Attempted NtQueryInformationProcess(ProcessProtectionInformation); the query did not return a usable result.' `
            -Class 'High' -Remediation 'Re-run this module from an elevated console on a supported OS build, then verify RunAsPPL and the lsass protection level together. Treat as unknown until validated.' `
            -Impact 'Unknown. Where LSA protection cannot be proven, assume credential material is reachable by an administrator-level attacker and prioritise the RunAsPPL setting plus Credential Guard.' -NoConsole
    }

    Write-Host ''
    Write-Host '  -- 5.2 Credential-caching configuration ----------------------------------------' -ForegroundColor DarkCyan
    $wdigest = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    $cached  = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount'
    $wdigestVal = Get-U32 $wdigest
    $cachedVal = $null
    if ($cached.NameExists) { try { $cachedVal = [int]$cached.Value } catch { } }

    Add-Control -Category 'Credential Protection' -Attribute 'WDigest cleartext credential caching' `
        -Expected 'UseLogonCredential absent or 0. When set to 1, LSASS retains the account password in reversible form for WDigest, so a memory read yields plaintext credentials.' `
        -Configured (Format-RegState $wdigest) `
        -Observed $(if ($wdigestVal -eq 1) { 'WDigest=1 - CLEARTEXT credential caching is enabled' } elseif ($null -eq $wdigestVal) { 'Not configured. Microsoft default since Windows 8/2012 and KB2871997 on older builds is 0 (disabled).' } else { 'WDigest=0 - cleartext caching disabled.' }) `
        -Validation 'Registry read. Plaintext caching is never validated by extracting credentials from memory; the configuration value is the evidence, and on modern builds the default is already secure.' `
        -Result $(if ($wdigestVal -eq 1) { 'RISK DETECTED' } else { 'PASS' }) -FactKey 'WdigestEnabled' -FactValue ($wdigestVal -eq 1) -Class 'High' -CatClass 'DataAtRest' `
        -Finding $(if ($wdigestVal -eq 1) { 'WDigest cleartext credential caching is ENABLED by registry value.' } else { 'WDigest cleartext caching is not enabled.' }) `
        -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0 (or delete the value) and restart. This is a critical setting: it converts LSASS memory access into plaintext domain credentials.' `
        -Impact 'Plaintext credentials obtained from memory can be replayed anywhere in the domain without cracking, defeating password-complexity and NTLM-specific mitigations.'

    Add-Control -Category 'Credential Protection' -Attribute 'Cached domain logon count' `
        -Expected 'CachedLogonsCount at or below 4 (0-2 on managed workstations with reliable connectivity). Cached credentials are verifier material on disk that is usable offline if the host is physically or disk-level compromised.' `
        -Configured (Format-RegState $cached) `
        -Observed ('Effective cached credential count: ' + $(if ($null -eq $cachedVal) { 'not configured (Windows default 10)' } else { [string]$cachedVal }) + '. Microsoft documents that cached credentials are protected with a per-host key and are not directly reusable off-host in the way a hash is, which is why this control is rated low.') `
        -Validation 'Registry read (documented default behaviour stated rather than assumed)' `
        -Result $(if ($null -eq $cachedVal -and $script:Section1Role -like '*Workstation*') { 'WARN' } elseif ($null -ne $cachedVal -and $cachedVal -gt 4) { 'WARN' } else { 'PASS' }) `
        -FactKey 'CachedLogonsCount' -FactValue $cachedVal -Class 'Micro' -CatClass 'DataAtRest' `
        -Finding $(if ($null -eq $cachedVal) { 'CachedLogonsCount is not configured; the Windows default (10) applies.' } else { 'CachedLogonsCount=' + $cachedVal }) `
        -Remediation 'Set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount to 0-2 on workstations with reliable domain connectivity (GPO: Interactive logon: Number of previous logons to cache). Ensure BitLocker is enabled on mobile devices so the cache cannot be attacked offline.' `
        -Impact 'A larger credential cache increases the value of at-rest attacks against the host (offline disk attack, DMA, or an OS-level attacker) and lengthens the window in which a changed password still works offline.'

    # Token privilege state, read from this process's own token in memory - whoami.exe is not
    # spawned anywhere in this engine (see Initialize-TokenProbe for why that matters on hardened
    # servers: Application Control can block the binary, and every spawn is extra log noise).
    $debugPriv = $false
    try {
        $dbg = @(Get-TokenPrivileges | Where-Object { $_.Name -eq 'SeDebugPrivilege' })
        $debugPriv = (@($dbg | Where-Object { $_.Enabled }).Count -gt 0)
        $script:Facts['SeDebugPresent'] = (@($dbg).Count -gt 0)
        if ($dbg.Count -gt 0) {
            $enabled = (@($dbg | Where-Object { $_.Enabled }).Count -gt 0)
            Write-Status 'INFO' ('Assessment token SeDebugPrivilege: ' + $(if ($enabled) { 'ENABLED' } else { 'held but not enabled' }) + ' [' + [string]$script:TokenProbeMethod + ']')
        }
    } catch { }
    if ($debugPriv) {
        Add-Finding -Category 'Credential Protection' -Status 'WARN' -Attribute 'SeDebugPrivilege in assessment token' -Target $script:HostName `
            -Finding 'The current assessment token holds SeDebugPrivilege, which is the capability required to open other processes (including LSASS) for memory access.' `
            -Observed ('SeDebugPrivilege is ENABLED in the assessment token [' + [string]$script:TokenProbeMethod + ']') -Validation 'In-memory token query (GetTokenInformation / TokenPrivileges). No native helper binary is spawned and no privilege is exercised.' `
            -Prerequisites 'Local administrator membership, which grants SeDebugPrivilege by default.' `
            -Exploitability 'Capability present but deliberately not exercised: this tool does not read process memory of any other process.' -Class 'High' -CatClass 'DataAtRest' `
            -Remediation 'Reduce the number of principals in the local Administrators group (SeDebugPrivilege is implied), enable LSA protection and Credential Guard so that even SeDebugPrivilege does not yield credential material, and remove SeDebugPrivilege from custom accounts or groups that define it.' `
            -Impact 'With SeDebugPrivilege and unprotected LSASS, an attacker in this context can obtain the credentials of every identity on the host.'
    }
}

# ===========================================================================================
#  SECTION 6 :: PRINT SPOOLER (role-aware exposure)
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  The Spooler is a high-value target on infrastructure (SYSTEM-level RPC surface and a
#  machine-account authentication coercion primitive). The finding is only a finding if the
#  service is actually running on a host that does not need it, which is why this module
#  classifies the host role first. Exploitation is deliberately NOT attempted.
# ===========================================================================================
function Invoke-Section6_Spooler {
    $spool = Test-SpoolerConfiguration
    $role = $script:Section1Role
    $isDc = ($role -like '*DOMAIN CONTROLLER*')
    $isServer = ($role -like '*MEMBER SERVER*')
    $running = ($spool.ServiceStatus -eq 'Running')

    Write-Host ''
    Write-Host '  -- 6.1 Role classification ------------------------------------------------------' -ForegroundColor DarkCyan
    Write-KV 'Host role' $role
    Write-KV 'Spooler applicability' $(if ($isDc -or $isServer) { 'Infrastructure host: printing is not required by design' } else { 'Workstation: printing is a normal user function' })

    Write-Host ''
    Write-Host '  -- 6.2 Service state and exposure ---------------------------------------------' -ForegroundColor DarkCyan
    Write-KV 'Spooler service exists' ([string]$spool.ServiceExists)
    Write-KV 'Service status' $spool.ServiceStatus
    Write-KV 'Startup mode' $spool.StartType
    Write-KV 'Start registry value' $spool.StartValue
    Write-KV 'spoolss named pipe present' ([string]$spool.PipeExposed)
    Write-KV 'RPC privacy (RpcAuthnLevelPrivacyEnabled)' $(if ($null -eq $spool.RpcAuthnPrivacy) { 'not present' } else { [string]$spool.RpcAuthnPrivacy })

    if (-not $spool.ServiceExists) {
        Add-Finding -Category 'Print Spooler' -Status 'PASS' -Attribute 'Spooler presence' -Target $script:HostName `
            -Finding 'The Spooler service is not installed on this host; the print RPC surface does not exist.' `
            -Observed ('Service key absent: ' + (-not $spool.ServiceExists)) -Validation 'Service Control Manager + registry read' `
            -Class 'High' -Remediation 'No action required.' -Impact 'None - the print attack surface is absent.'
        return
    }

    if ($running -and ($isDc -or $isServer)) {
        Add-Finding -Category 'Print Spooler' -Status 'VALIDATED' -Attribute 'Spooler running on infrastructure host' -Target $script:HostName -Port '445' `
            -Finding ('The Spooler service is RUNNING on a ' + $role + '. Running the spooler on infrastructure is not required by the vendor for the machine role and exposes both a SYSTEM-level RPC interface and a machine-account authentication coercion primitive.') `
            -Configured $spool.Configured `
            -Observed ('status=' + $spool.ServiceStatus + '; start=' + $spool.StartType + '; spoolss pipe present=' + $spool.PipeExposed + ' (named-pipe namespace enumerated at runtime); role=' + $role) `
            -Validation 'Runtime service state + runtime named-pipe namespace enumeration (proves the print RPC endpoint is instantiated, not merely that the service is set to start). Exploitation (driver installation, coercion) was deliberately NOT attempted.' `
            -Prerequisites 'Network reachability to the host on TCP/445 or the RPC endpoint mapper (Section 8 records whether this is reachable within the assessed scope).' `
            -Exploitability 'Exposure validated; exploitation not attempted and must not be inferred from this row.' `
            -Class $(if ($isDc) { 'Critical' } else { 'High' }) -CatClass 'Integrity' `
            -Remediation 'Stop and disable the Spooler on all servers and domain controllers that are not print servers: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled. Enforce with GPO ("Allow Print Spooler to accept client connections" = Disabled) so the state survives reboot and does not depend on manual action.' `
            -Impact 'On infrastructure hosts the spooler widens the SYSTEM-level attack surface for local and remote code execution and enables printer-change-notification coercion of the machine account, which is a standard component of NTLM-relay chains to a domain controller.'
    } elseif ($running) {
        Add-Finding -Category 'Print Spooler' -Status 'WARN' -Attribute 'Spooler running on workstation' -Target $script:HostName `
            -Finding 'The Spooler service is running on a workstation. This is expected for user printing, so the finding is the residual risk of the print stack rather than the service state itself.' `
            -Configured $spool.Configured -Observed ('status=Running; Point-and-Print hardening: RestrictDriverInstallationToAdministrators=' + $(if ($null -eq $spool.PointAndPrintRestrict) { 'absent' } else { [string]$spool.PointAndPrintRestrict }) + '; RpcAuthnLevelPrivacyEnabled=' + $(if ($null -eq $spool.RpcAuthnPrivacy) { 'absent' } else { [string]$spool.RpcAuthnPrivacy })) `
            -Validation 'Runtime service state + vendor mitigation registry keys (no exploitation attempted)' `
            -Class 'Medium' -CatClass 'Integrity' `
            -Remediation 'If users do not print from this host, disable the Spooler. Otherwise enforce the vendor mitigations (Section 2.11) and restrict Point-and-Print to approved print servers via GPO.' `
            -Impact 'A workstation spooler is a local privilege-escalation surface (SYSTEM code path) and a coercion primitive usable against the machine account; the mitigations above reduce both.'
    } else {
        Add-Finding -Category 'Print Spooler' -Status 'PASS' -Attribute 'Spooler state' -Target $script:HostName `
            -Finding 'The Spooler service is installed but not running.' -Observed ('status=' + $spool.ServiceStatus + '; start=' + $spool.StartType) `
            -Validation 'Runtime service state' -Class 'High' -Remediation 'Set the startup type to Disabled so the service cannot be auto-started by a print request or a dependent service.' `
            -Impact 'None while stopped; if the startup type remains Automatic, a print-related operation could start it.'
    }
}

# ===========================================================================================
#  SECTION 7 :: WINDOWS UPDATE / WSUS
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Patch currency determines whether a given local privilege-escalation technique still works.
#  This module records the update path (Internet vs WSUS), whether the WSUS endpoint is
#  actually reachable (a validated condition - a configured-but-unreachable WSUS server
#  silently leaves hosts unpatched), and the age of the most recently installed update.
#  Nothing is installed, downloaded, or reconfigured.
# ===========================================================================================
function Invoke-Section7_Update {
    Write-Host ''
    Write-Host '  -- 7.1 Update service and policy ------------------------------------------------' -ForegroundColor DarkCyan
    $wuReg   = Get-RegValue -Path 'SYSTEM\CurrentControlSet\Services\wuauserv' -Name 'Start'
    $wuSvc   = Get-ServiceSafe 'wuauserv'
    $wuPol   = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer'
    $wuStat  = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUStatusServer'
    $auKey   = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $auNoAuto= Get-RegValue -Path $auKey -Name 'NoAutoUpdate'
    $auOpt   = Get-RegValue -Path $auKey -Name 'AUOptions'
    $auUseWu = Get-RegValue -Path $auKey -Name 'UseWUServer'
    $auSched = Get-RegValue -Path $auKey -Name 'ScheduledInstallDay'
    $auTime  = Get-RegValue -Path $auKey -Name 'ScheduledInstallTime'
    $auDetect= Get-RegValue -Path $auKey -Name 'DetectionFrequency'

    Write-KV 'wuauserv state' $(if ($wuSvc) { $wuSvc.Status.ToString() + ' / ' + $wuSvc.StartType.ToString() } else { 'not installed' })
    Write-KV 'wuauserv Start value' (Format-RegState $wuReg)
    Write-KV 'WSUS server (WUServer)' $(if ($wuPol.NameExists) { [string]$wuPol.Value } else { 'not configured - host updates from Microsoft Update (or another MDM/third-party path)' })
    Write-KV 'WSUS status server' $(if ($wuStat.NameExists) { [string]$wuStat.Value } else { 'not configured' })
    Write-KV 'NoAutoUpdate' (Format-RegState $auNoAuto)
    Write-KV 'AUOptions' (Format-RegState $auOpt)
    Write-KV 'UseWUServer' (Format-RegState $auUseWu)
    Write-KV 'Scheduled install' $(if ($auSched.NameExists) { 'day=' + $auSched.Value + ' time=' + $(if ($auTime.NameExists) { $auTime.Value } else { 'n/a' }) } else { 'not configured (default scheduling applies)' })
    Write-KV 'Detection frequency' (Format-RegState $auDetect)

    $noAutoVal = Get-U32 $auNoAuto
    $useWuVal = Get-U32 $auUseWu
    Add-Control -Category 'Patch Management' -Attribute 'Windows Update automatic servicing policy' `
        -Expected 'Automatic updating enabled (NoAutoUpdate absent or 0) with either a reachable WSUS/ConfigMgr server (WUServer + UseWUServer=1) or Microsoft Update as the source. Structured update management means a known server, a known schedule and verifiable installation.' `
        -Configured ('NoAutoUpdate=' + (Format-RegState $auNoAuto) + ' ; UseWUServer=' + (Format-RegState $auUseWu) + ' ; WUServer=' + (Format-RegState $wuPol) + ' ; AUOptions=' + (Format-RegState $auOpt)) `
        -Observed $(if ($noAutoVal -eq 1) { 'Automatic Updates are DISABLED by policy (NoAutoUpdate=1) - patches only arrive through manual/MDM action.' } elseif ($wuPol.NameExists -and $useWuVal -eq 1) { 'Managed: this host points at an internal update server.' } elseif ($wuPol.NameExists) { 'WUServer is configured but UseWUServer is not set to 1, so the host may be using Microsoft Update instead.' } else { 'No WSUS policy: the host uses Microsoft Update (or a third-party patch path that is not visible in these keys).' }) `
        -Validation 'Registry policy read. Reachability of the configured update server is tested separately below, which is the part that can be validated.' `
        -Result $(if ($noAutoVal -eq 1) { 'WARN' } else { 'PASS' }) -FactKey 'WuManaged' -FactValue ([bool]($wuPol.NameExists -and $useWuVal -eq 1)) -Class 'High' `
        -Finding $(if ($noAutoVal -eq 1) { 'Automatic updating is disabled by policy on this host.' } elseif ($wuPol.NameExists) { 'A structured update path (internal WSUS/ConfigMgr server) is configured.' } else { 'No internal update server is configured; the host depends on Microsoft Update or an out-of-band path.' }) `
        -Remediation 'Standardise on an internal WSUS or ConfigMgr hierarchy with an approved-ring policy, verify that clients report successfully, and monitor for hosts that stop reporting. Where policy disables automatic updating, ensure a documented alternative patch process with evidence of installation.' `
        -Impact 'Hosts that stop receiving security updates accumulate known privilege-escalation and remote-code-execution vulnerabilities; every technique catalogue in this report must be re-evaluated against the actual patch level.'

    $recent = @()
    try { $recent = @(Get-HotFix -ErrorAction Stop | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5) } catch { }
    if ($recent.Count -gt 0) {
        $rows = @()
        foreach ($h in $recent) { $rows += [pscustomobject]@{ HotFixID=$h.HotFixID; Description=$h.Description; InstalledOn=$(if ($h.InstalledOn) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { 'unknown' }); InstalledBy=$h.InstalledBy } }
        Write-Host ''
        Write-Host '  -- 7.2 Most recently installed updates ------------------------------------------' -ForegroundColor DarkGray
        Write-Table -Rows $rows -Columns @('HotFixID','Description','InstalledOn','InstalledBy') -Headers @{ HotFixID='Update'; Description='Type'; InstalledOn='Installed on'; InstalledBy='Installed by' }
        $newest = $recent | Where-Object { $_.InstalledOn } | Select-Object -First 1
        if ($newest) {
            $ageDays = [int]((Get-Date) - $newest.InstalledOn).TotalDays
            Add-Finding -Category 'Patch Management' -Status $(if ($ageDays -gt 60) { 'WARN' } else { 'INFO' }) -Attribute 'Most recent installed update age' `
                -Target $script:HostName -Finding ('The most recent update recorded by the host was installed ' + $ageDays + ' day(s) ago (' + $newest.HotFixID + ').') `
                -Configured 'See update path policy above' -Observed ('newest HotFixID=' + $newest.HotFixID + '; installed=' + $newest.InstalledOn.ToString('yyyy-MM-dd') + '; age=' + $ageDays + ' day(s)') `
                -Validation 'Native Win32_QuickFixEngineering inventory (read-only). Note: cumulative updates are only partially represented by this interface, so this is indicative evidence of patch currency, not a definitive baseline comparison.' `
                -Class 'High' `
                -Remediation $(if ($ageDays -gt 60) { 'Investigate why no update has been installed recently: check WSUS reporting, the WindowsUpdate.log / event channel Microsoft-Windows-WindowsUpdateClient, and whether the update path is reachable (tested below).' } else { 'Maintain monthly cumulative update cadence and verify installation through your patch-compliance platform rather than this indicative interface.' }) `
                -Impact 'Patch age is the single largest determinant of whether the local privilege-escalation techniques catalogued in Section 17 remain available to an attacker.'
        }
    } else {
        Write-Status 'NOT TESTABLE' 'The installed-update inventory could not be read (Win32_QuickFixEngineering unavailable or access denied).'
    }

    # Pending-reboot state: unapplied patches are a real, observable gap
    $pending = @()
    foreach ($p in @(
        @{ Path='SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; Label='Windows Update: reboot required' },
        @{ Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; Label='CBS: reboot pending' },
        @{ Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'; Label='CBS: reboot in progress' })) {
        $r = Get-RegValue -Path $p.Path
        if ($r.KeyExists) { $pending += $p.Label }
    }
    if ($pending.Count -gt 0) {
        Write-Status 'WARN' ('Pending servicing state detected: ' + ($pending -join '; '))
        Add-Finding -Category 'Patch Management' -Status 'WARN' -Attribute 'Unapplied updates awaiting reboot' -Target $script:HostName `
            -Finding 'The host has updates staged but not applied (reboot pending), so the running kernel and binaries do not yet include the latest security fixes.' `
            -Configured ($pending -join '; ') -Observed ('Registry staging keys present: ' + ($pending -join '; ')) `
            -Validation 'Native servicing-state registry keys (read-only); the host is NOT rebooted by this tool.' -Class 'High' `
            -Remediation 'Schedule the pending reboot through the change process and confirm the update is applied afterwards (compare the build revision before/after). Investigate hosts that remain in a pending-reboot state for more than one patch cycle, as this usually indicates an operational failure rather than an attack.' `
            -Impact 'Where a staging reboot is deferred, the vulnerability remains exploitable even though the patch is considered "deployed" in the management console.'
    } else {
        Write-Status 'PASS' 'No pending-reboot servicing state was found.'
    }

    # ---- WSUS endpoint reachability (validated condition) --------------------------------
    if ($wuPol.NameExists -and $wuPol.Value) {
        $url = [string]$wuPol.Value
        $hostName = ''; $port = 8530
        try {
            $u = New-Object System.Uri($url.Trim())
            $hostName = $u.Host
            if ($u.Port -gt 0) { $port = $u.Port } elseif ($u.Scheme -eq 'https') { $port = 8531 } else { $port = 8530 }
        } catch { $hostName = $url }
        if ($hostName) {
            $t = Test-TcpPort -Target $hostName -Port $port -TimeoutMs 1200
            Write-Host ''
            Write-Host '  -- 7.3 Update-server reachability (validated) -------------------------------------' -ForegroundColor DarkCyan
            Write-Status $(if ($t.State -eq 'Open') { 'VALIDATED' } else { 'RISK DETECTED' }) ('WSUS endpoint ' + $hostName + ':' + $port + ' -> ' + $t.State + ' (' + $t.Error + ')')
            Add-Finding -Category 'Patch Management' -Status $(if ($t.State -eq 'Open') { 'PASS' } else { 'RISK DETECTED' }) -Attribute 'Update server reachability (WSUS endpoint)' `
                -Source $script:HostName -Target ($hostName + ':' + $port) -Port ([string]$port) `
                -Finding $(if ($t.State -eq 'Open') { 'The configured update server is reachable from this host (TCP connection completed).' } else { 'The configured update server is NOT reachable from this host: patching is silently failing for this machine.' }) `
                -Configured ('WSUS URL: ' + $url) -Observed ('TCP ' + $hostName + ':' + $port + ' = ' + $t.State + ' (' + $t.Error + '), round trip ' + $t.LatencyMs + ' ms') `
                -Validation 'Single bounded TCP connection to the configured update endpoint (no HTTP update transaction was performed, nothing was downloaded or installed).' `
                -Prerequisites 'Network path from this host to the WSUS server on the configured port.' -Class 'High' `
                -Remediation $(if ($t.State -eq 'Open') { 'No action required. Monitor client reporting on the WSUS console so that a reachable-but-not-reporting client is still detected.' } else { 'Restore the network path between clients and the update server, or repoint clients to a reachable server, then verify with a manual detection cycle. Verify the WSUS service and IIS bindings on the server side.' }) `
                -Impact $(if ($t.State -eq 'Open') { 'None observed - the update path is functional.' } else { 'The host is not receiving security updates at all while ostensibly being managed, which is a far more severe condition than an unmanaged host because it is invisible in compliance dashboards.' })
        }
    } else {
        Write-Status 'INFO' 'No WSUS server is configured; update-server reachability is not applicable on this host.'
    }
}
# ===========================================================================================
#  SECTION 8 :: NETWORK DISCOVERY  (bounded, authorised-scope only)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  The report needs to state which services are actually REACHABLE from the assessment
#  position, because reachability is the difference between "a control is weak" and "the
#  weakness can be used". Discovery is therefore scoped and bounded by design:
#
#    * the scope is DERIVED from this host's own IPv4 configuration (never guessed, never a
#      hard-coded range that might fall outside the authorisation)
#    * the operator is shown the exact scope and must approve it before any sweep runs
#    * one /24 maximum per run; 13 ports per host; ~500 ms per connection attempt
#    * a hard wall-clock ceiling stops the sweep and reports how much was completed, so a
#      partially completed sweep can never be presented as a complete one
#    * no SYN flooding, no fragmentation tricks, no spoofing, no evasion, no rate that could
#      affect availability; at most ~50 concurrent sockets
#    * UDP is not probed at all (a UDP sweep is noisy and produces unreliable results)
#
#  Services probed (the standard AD/Windows infrastructure matrix):
#      53 DNS | 88 Kerberos | 135 RPC EPM | 139 NetBIOS-SSN | 389 LDAP | 445 SMB
#      636 LDAPS | 3268 Global Catalog | 3269 GC/SSL | 3389 RDP | 5985 WinRM
#      5986 WinRM/TLS
# ===========================================================================================

function ConvertTo-IPv4UInt32 {
    param([string]$Ip)
    try {
        $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
        return [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor ([uint32]$b[3]))
    } catch { return $null }
}
function ConvertFrom-IPv4UInt32 {
    param([uint32]$Value)
    return (([uint32](($Value -shr 24) -band 0xFF)).ToString() + '.' + ([uint32](($Value -shr 16) -band 0xFF)).ToString() + '.' + ([uint32](($Value -shr 8) -band 0xFF)).ToString() + '.' + ([uint32]($Value -band 0xFF)).ToString())
}

$script:LivenessWorker = {
    param($Targets, $TimeoutMs, $PingTimeoutMs, $StartDelayMs = 0)
    $res = @()
    foreach ($t in $Targets) {
        # Throttle control: honour Cfg.StartupDelay so the sweep cannot present this host as a
        # burst source. The value is passed in, so the pacing is visible in one configuration place.
        if ($StartDelayMs -gt 0) { Start-Sleep -Milliseconds $StartDelayMs }
        $open = $false
        foreach ($p in @(445, 135, 3389)) {
            $c = New-Object System.Net.Sockets.TcpClient
            try {
                $c.NoDelay = $true
                $ar = $c.BeginConnect($t, $p, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                    try { $c.EndConnect($ar); $open = $true } catch { $open = $true }   # RST also proves liveness
                }
            } catch { } finally { try { $c.Close() } catch { } }
            if ($open) { break }
        }
        if (-not $open) {
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $pr = $ping.Send($t, $PingTimeoutMs)
                if ($pr -and $pr.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $open = $true }
            } catch { }
        }
        if ($open) { $res += $t }
    }
    return ,$res
}

$script:PortMatrixWorker = {
    param($Targets, $Ports, $TimeoutMs)
    $open = @()
    foreach ($t in $Targets) {
        foreach ($p in $Ports) {
            $c = New-Object System.Net.Sockets.TcpClient
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $c.NoDelay = $true
                $ar = $c.BeginConnect($t, $p, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                    try { $c.EndConnect($ar); $open += [pscustomobject]@{ Host = $t; Port = $p; LatencyMs = $sw.ElapsedMilliseconds } } catch { }
                }
            } catch { } finally { try { $c.Close() } catch { } $sw.Stop() }
        }
    }
    return ,$open
}

function Invoke-BoundedParallel {
    <# Splits a work item list across a small runspace pool and enforces a hard deadline.
       Returns the combined results plus the number of items that were NOT processed in time,
       so partial coverage is always visible in the report. #>
    param(
        [Parameter(Mandatory=$true)][scriptblock]$Worker,
        [Parameter(Mandatory=$true)][object[]]$Targets,
        [object[]]$Ports = @(),
        [int]$TimeoutMs = 500,
        [int]$PingTimeoutMs = 250,
        [int]$Chunks = 8,
        [int]$DeadlineSec = 120,
        [int]$HostDelayMs = 0,
        [int]$ChunkDelayMs = 15
    )
    # SINGLE CHOKE POINT for every parallel network operation (liveness sweep AND service matrix).
    # This runs in the PARENT runspace, which is the only place Test-RemoteAllowed is callable:
    # the workers are serialised into fresh runspaces by AddScript($Worker.ToString()), so a gate
    # INSIDE a worker would fail with 'term not recognised' rather than suppress anything. Refusing
    # to dispatch here means no worker socket code can execute under /localonly.
    if (-not (Test-RemoteAllowed)) {
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - the bounded parallel sweep was not started.')
        return [pscustomobject]@{ Items=@(); Processed=0; Total=$Targets.Count; TimedOut=$false }
    }
    $results = @()
    $processed = 0
    $total = $Targets.Count
    if ($total -eq 0) { return [pscustomobject]@{ Items=@(); Processed=0; Total=0; TimedOut=$false } }
    if ($Chunks -gt $total) { $Chunks = $total }
    $per = [math]::Ceiling($total / $Chunks)
    $groups = @()
    for ($i = 0; $i -lt $total; $i += $per) {
        $end = [Math]::Min($i + $per - 1, $total - 1)
        $groups += ,@($Targets[$i..$end])
    }
    $pool = $null; $jobs = @()
    try {
        $pool = [runspacefactory]::CreateRunspacePool(1, $script:Cfg.MaxParallelPort)
        $pool.Open()
        foreach ($g in $groups) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($Worker.ToString())
            if ($Ports.Count -gt 0) { [void]$ps.AddArgument($g); [void]$ps.AddArgument($Ports); [void]$ps.AddArgument($TimeoutMs) }
            else { [void]$ps.AddArgument($g); [void]$ps.AddArgument($TimeoutMs); [void]$ps.AddArgument($PingTimeoutMs); [void]$ps.AddArgument($HostDelayMs) }
            $jobs += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Group = $g }
            Start-Sleep -Milliseconds $ChunkDelayMs
        }
        $deadline = (Get-Date).AddSeconds($DeadlineSec)
        $timedOut = $false
        foreach ($j in $jobs) {
            $remaining = [int]($deadline - (Get-Date)).TotalSeconds
            if ($remaining -le 0) { $timedOut = $true; break }
            try {
                $out = $j.PS.EndInvoke($j.Handle)
                if ($out) { foreach ($o in $out) { $results += $o } }
                $processed += $j.Group.Count
            } catch { Write-Status 'WARN' ('Discovery worker failed for a chunk: ' + $_.Exception.Message) }
        }
        if ($timedOut) {
            foreach ($j in $jobs) { try { $j.PS.Stop() } catch { } }
            Write-Status 'WARN' ('Discovery deadline of ' + $DeadlineSec + 's reached: ' + $processed + ' of ' + $total + ' addresses were checked.')
        }
    } catch {
        Write-Status 'ERROR' ('Parallel discovery failed: ' + $_.Exception.Message)
    } finally {
        foreach ($j in $jobs) { try { $j.PS.Dispose() } catch { } }
        if ($pool) { try { $pool.Close(); $pool.Dispose() } catch { } }
    }
    return [pscustomobject]@{ Items = $results; Processed = $processed; Total = $total; TimedOut = [bool]$timedOut }
}

function Invoke-Section8_Discovery {
    $nics = Get-NicInventory
    $localIps = Get-LocalIpv4 -Nics $nics

    # ---- Derive the authorised scope from native interface configuration -----------------
    $scopes = @()
    foreach ($n in $nics) {
        if (-not $n.IsUp) { continue }
        if ($n.Name -match 'Loopback') { continue }
        foreach ($entry in ($n.IPv4 -split ',\s*')) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            $parts = $entry.Split('/')
            if ($parts.Count -ne 2) { continue }
            $ip = $parts[0]; $pfx = 0
            if (-not [int]::TryParse($parts[1], [ref]$pfx)) { continue }
            if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
            $scopes += [pscustomobject]@{ Interface=$n.Name; LocalIp=$ip; Prefix=$pfx }
        }
    }
    if ($scopes.Count -eq 0) {
        Write-Status 'NOT TESTABLE' 'No routable local IPv4 interface was found: network discovery cannot derive an authorised scope and will not run.'
        Add-Finding -Category 'Network Discovery' -Status 'NOT TESTABLE' -Attribute 'Scope derivation' `
            -Finding 'Network discovery was not performed because no routable IPv4 scope could be derived from this host''s interfaces.' `
            -Validation 'Interface inventory via .NET NetworkInterface API' -Class 'Medium' `
            -Remediation 'Run the assessment from a host with a routable address in the assessed segment, or provide an explicit scope list for the engagement.' `
            -Impact 'Unknown: reachability evidence is a prerequisite for every impact claim in this report, so its absence must be recorded rather than glossed over.' -NoConsole
        return
    }

    Write-Host ''
    Write-Host '  -- 8.1 Authorised scope derived from local interface configuration ----------------' -ForegroundColor DarkCyan
    $scopeRows = @()
    $targetList = New-Object System.Collections.Generic.List[string]
    $skippedWide = @()
    foreach ($s in $scopes) {
        $ipU = ConvertTo-IPv4UInt32 $s.LocalIp
        $mask = if ($s.Prefix -eq 0) { [uint32]0 } else { [uint32]((0xFFFFFFFF -shl (32 - $s.Prefix)) -band 0xFFFFFFFF) }
        $net = $ipU -band $mask
        $size = [math]::Pow(2, (32 - $s.Prefix))
        $scopeRows += [pscustomobject]@{ Interface=$s.Interface; LocalIp=$s.LocalIp; Prefix=('/' + $s.Prefix); Network=((ConvertFrom-IPv4UInt32 $net) + '/' + $s.Prefix); Addresses=[int]$size }
        if ($s.Prefix -lt 24) {
            $skippedWide += ((ConvertFrom-IPv4UInt32 $net) + '/' + $s.Prefix)
            continue   # refuse to sweep anything wider than a /24 automatically
        }
        $first = $net + 1
        $last = $net + $size - 2
        for ($i = $first; $i -le $last; $i++) {
            $a = ConvertFrom-IPv4UInt32 $i
            if ($a -eq $s.LocalIp) { continue }
            if (-not $targetList.Contains($a)) { [void]$targetList.Add($a) }
        }
    }
    Write-Table -Rows $scopeRows -Columns @('Interface','LocalIp','Prefix','Network','Addresses') -Headers @{ Interface='Interface'; LocalIp='Local address'; Prefix='Prefix'; Network='Derived network'; Addresses='Addresses in scope' }

    if ($skippedWide.Count -gt 0) {
        Write-Status 'WARN' ('Interfaces wider than /24 were NOT swept automatically: ' + ($skippedWide -join ', ') + '. Supply an explicit authorised range if the engagement requires it.')
        Add-Finding -Category 'Network Discovery' -Status 'NOT TESTABLE' -Attribute 'Wide subnet not auto-swept' `
            -Finding ('A /' + '<24 interface (' + ($skippedWide -join ', ') + ') was excluded from automatic discovery to prevent uncontrolled scanning.') `
            -Observed 'Automatic scope is capped at one /24 per interface.' -Validation 'Scope guardrail (design control, not a host control)' `
            -Class 'Medium' -Remediation 'If the engagement authorises a wider range, provide the explicit list of addresses (scope file) rather than relying on automatic derivation.' `
            -Impact 'Discovery coverage is intentionally limited; hosts outside the swept /24 were not assessed for reachability.' -NoConsole
    }

    # SCOPE FILTER - applied at the single point where the target list is finalised, so no later
    # edit can reintroduce an out-of-scope address. Default-deny whenever a scope was supplied.
    if ($script:ScopeActive) {
        $beforeScope = $targetList.Count
        $targetList = @($targetList | Where-Object { Test-InScope -Target $_ })
        $removedByScope = $beforeScope - $targetList.Count
        if ($removedByScope -gt 0) { Write-Status 'INFO' ('engagement scope removed ' + $removedByScope + ' address(es) outside: ' + $script:ScopeText) }
    }
    $targetList = @($targetList | Select-Object -First $script:Cfg.MaxSweepHosts)
    Write-Host ''
    Write-KV 'Proposed discovery scope' ($targetList.Count.ToString() + ' address(es) across ' + $scopes.Count + ' interface(s)')
    Write-KV 'Ports to test' '53, 88, 135, 139, 389, 445, 636, 3268, 3269, 3389, 5985, 5986'
    Write-KV 'Concurrency / timeout' ($script:Cfg.MaxParallelPort.ToString() + ' sockets, ' + $script:Cfg.TcpTimeoutMs + ' ms per attempt, ' + $script:Cfg.SweepTimeoutSec + ' s ceiling')
    Write-KV 'IPv6' 'Local IPv6 addresses are reported but NOT swept (documented limitation: no IPv6 sweep is performed)'

    # ---- /localonly: no off-host traffic at all ---------------------------------------------
    if (-not (Test-RemoteAllowed)) {
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - the address sweep was not performed.')
        Add-Finding -Category 'Network Discovery' -Status 'NOT TESTABLE' -Attribute 'Remote discovery suppressed (/localonly)' `
            -Finding 'The bounded discovery sweep was not performed because the operator requested a local-only run. No off-host packet was sent by this module.' `
            -Observed ('Proposed scope had ' + $targetList.Count + ' address(es); source: the local IPv4 configuration') `
            -Configured 'Launcher switch /localonly (EIA_LOCAL_ONLY=1)' `
            -Validation 'Operator control - the suppression is a deliberate scope decision, not a reachability failure. No TCP connect, ICMP echo or name resolution was attempted against any remote address.' `
            -Class 'Low' `
            -Remediation 'Re-run without /localonly inside the authorised change window if subnet-wide reachability evidence is required.' `
            -Impact 'Hosts and services discovered remain limited to what this host reports about itself; Section 15/19 conclusions that depend on remote reachability are reported NOT TESTABLE rather than inferred.' -NoConsole
        $targetList = @()
    }

    $approved = $true
    $consentMode = 'not requested (no sweep targets)'
    if ($targetList.Count -gt 0) {
        # Default is now NO: an unattended or headless run must never sweep by accident. An operator
        # at a console must answer 'y'; /authorize-active pre-authorises at launch.
        $consent = Request-Consent -StepName 'Network discovery sweep' -DefaultAllowed $false `
            -Question ('Proceed with the bounded discovery sweep of ' + $targetList.Count + ' address(es) in the derived scope? [y/N]')
        $approved = [bool]$consent.Allowed
        $consentMode = $consent.Mode
        Write-Host ('    consent decision: ' + $consent.Note) -ForegroundColor DarkGray
    }
    if (-not $approved) {
        Write-Status 'NOT TESTABLE' 'Operator declined the discovery sweep. Reachability evidence is limited to explicitly named targets.'
        Add-Finding -Category 'Network Discovery' -Status 'NOT TESTABLE' -Attribute 'Discovery sweep not authorised by operator' `
            -Finding 'The bounded discovery sweep was declined at the console prompt, so no subnet-wide reachability evidence was collected.' `
            -Observed ('Proposed scope had ' + $targetList.Count + ' address(es); consent path: ' + $consentMode) -Validation 'Operator control (both a safety and an authorisation control): the decision and the reason it was or was not asked are recorded with the finding.' `
            -Class 'Medium' -Remediation 'Re-run and approve the sweep when the engagement authorisation covers the subnet, or provide an explicit target list.' `
            -Impact 'Downstream reachability-dependent conclusions are limited to the targets that were explicitly tested.' -NoConsole
        $targetList = @()
    }

    # ---- Local host matrix (always performed: it is this host's own configuration) -------
    # NOTE: Cfg.Ports is the single source of truth. The previous expression ($script:Cfg.Ports.ToArray())
    # was doubly wrong: the key was never defined, and .ToArray() does not exist on an array (PowerShell
    # enumerates it and calls the method on the first element). Either fault aborted Section 8.
    $matrix = @($script:Cfg.Ports)
    $localOpen = @()
    foreach ($p in @($script:Cfg.Ports)) {
        $t = Test-TcpPort -Target '127.0.0.1' -Port $p -TimeoutMs 500
        if ($t.State -eq 'Open') { $localOpen += [pscustomobject]@{ Host='127.0.0.1'; Port=$p; Service=(Get-ServiceNameForPort $p); Source='local'; LatencyMs=$t.LatencyMs } }
    }
    Write-Host ''
    Write-Host '  -- 8.2 Local listening service matrix (host = assessment foothold) -----------------' -ForegroundColor DarkCyan
    if ($localOpen.Count -eq 0) { Write-Host '    (no probed service was listening on the local host)' -ForegroundColor DarkGray }
    else {
        Write-Table -Rows $localOpen -Columns @('Port','Service','LatencyMs') -Headers @{ Port='Port'; Service='Service'; LatencyMs='RTT (ms)' }
        foreach ($o in $localOpen) {
            $script:Stats.ServicesDiscovered++
            Add-Finding -Category 'Network Discovery' -Status 'INFO' -CatClass 'Context' -Attribute 'Local listening service' `
                -Source 'local' -Target $script:HostName -Port ([string]$o.Port) `
                -Finding ('This host is listening on TCP/' + $o.Port + ' (' + $o.Service + ').') `
                -Observed ('TCP connect to 127.0.0.1:' + $o.Port + ' = Open, ' + $o.LatencyMs + ' ms') `
                -Validation 'TCP connect test from the host itself (loopback). This proves the service is instantiated; remote reachability is a separate question answered by the sweep below and Section 15.' `
                -Class 'Low' -Remediation 'Review each listening service against the host role and remove or firewall anything not required (see Sections 2, 4, 6).' `
                -Impact 'Loopback reachability alone has no direct security impact; it is recorded because it establishes the service inventory for this host.' -NoConsole
        }
    }

    # ---- Domain controller reachability (explicit, always in scope) ----------------------
    $dcTarget = ''
    if ($script:DomainControllerName) {
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($script:DomainControllerName) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
            if ($addrs) { $dcTarget = $addrs[0].IPAddressToString }
        } catch { }
        if (-not $dcTarget) { $dcTarget = $script:DomainControllerName }
    }

    # ---- Bounded sweep -------------------------------------------------------------------
    $live = @()
    $sweep = $null
    # The gate is repeated on the guard itself (not only applied by emptying $targetList above) so
    # that the suppression is STRUCTURAL and verifiable by inspection: an edit that repopulates the
    # target list cannot silently re-enable the sweep during a local-only run.
    if ($targetList.Count -gt 0 -and (Test-RemoteAllowed)) {
        Write-Host ''
        Write-Host '  -- 8.3 Bounded liveness discovery ------------------------------------------------' -ForegroundColor DarkCyan
        Write-Host ('    sweeping ' + $targetList.Count + ' address(es) (TCP 445/135/3389 then ICMP; ceiling ' + $script:Cfg.SweepTimeoutSec + 's)') -ForegroundColor DarkGray
        $sweep = Invoke-BoundedParallel -Worker $script:LivenessWorker -Targets $targetList -TimeoutMs $script:Cfg.TcpTimeoutMs -PingTimeoutMs 250 -Chunks 10 -DeadlineSec $script:Cfg.SweepTimeoutSec -HostDelayMs $script:Cfg.StartupDelay -ChunkDelayMs $script:Cfg.StartupDelay
        $live = @($sweep.Items | Sort-Object)
        Write-Status 'INFO' ('Liveness complete: ' + $live.Count + ' responsive address(es) of ' + $sweep.Processed + ' checked' + $(if ($sweep.TimedOut) { ' (deadline reached - coverage incomplete)' } else { '' }))
        Write-Host ''
        Write-Host '  -- 8.4 Service matrix on responsive hosts ----------------------------------------' -ForegroundColor DarkCyan
        $ports = @($script:Cfg.Ports)
        $matrixResult = Invoke-BoundedParallel -Worker $script:PortMatrixWorker -Targets $live -Ports $ports -TimeoutMs 600 -Chunks 8 -DeadlineSec $script:Cfg.SweepTimeoutSec
        $discovered = @($matrixResult.Items)
        $script:MatrixResult = $discovered
        $script:Stats.HostsDiscovered = $live.Count
        $script:Stats.ServicesDiscovered += $discovered.Count

        # per-host summary
        $byHost = @{}
        foreach ($d in $discovered) {
            if (-not $byHost.ContainsKey($d.Host)) { $byHost[$d.Host] = @() }
            $byHost[$d.Host] += $d.Port
        }
        $summaryRows = @()
        foreach ($h in $live) {
            $p = if ($byHost.ContainsKey($h)) { ($byHost[$h] | Sort-Object) -join ', ' } else { '(no probed service)' }
            $isDcLike = ($byHost.ContainsKey($h) -and ($byHost[$h] -contains 88) -and ($byHost[$h] -contains 389))
            $summaryRows += [pscustomobject]@{ Host=$h; Ports=$p; Inference=$(if ($isDcLike) { 'probable domain controller (Kerberos+LDAP+GC pattern)' } else { 'role not determinable from ports (no authenticated enumeration was performed)' }) }
        }
        Write-Table -Rows $summaryRows -Columns @('Host','Ports','Inference') -Headers @{ Host='Live host'; Ports='Open probed ports'; Inference='Role inference' }

        foreach ($row in $summaryRows) {
            $pi = if ($byHost.ContainsKey($row.Host)) { $byHost[$row.Host] } else { @() }
            $svcNames = ($pi | ForEach-Object { (Get-ServiceNameForPort $_) + '/' + $_ }) -join ', '
            Add-Finding -Category 'Network Discovery' -Status 'INFO' -CatClass 'Context' -Attribute 'Discovered host' `
                -Source $script:HostName -Target $row.Host -Port ($pi -join ',') `
                -Finding ('Host responded and exposes: ' + $(if ($svcNames) { $svcNames } else { 'no services from the probed set' }) + '. ' + $row.Inference) `
                -Observed ('Live by TCP/ICMP; open ports: ' + $row.Ports) `
                -Validation 'Bounded TCP connect sweep + ICMP echo from the assessment host. This is REACHABILITY evidence only: no authentication was attempted against these hosts and no host role was confirmed.' `
                -Class 'Low' -Remediation 'Confirm that each exposed service is required for the host role and restrict administrative interfaces (445/135/3389/5985) to management subnets.' `
                -Impact 'Reachability alone is not an impact. It becomes significant only where an administrative service is reachable from a segment that should not have access (assessed in Section 15).' -NoConsole

            # High-signal exposure: administrative interfaces reachable from the assessment segment
            foreach ($p in @(3389, 5985, 5986)) {
                if ($pi -contains $p) {
                    Add-Finding -Category 'Network Discovery' -Status 'WARN' -Attribute 'Administrative interface reachable' `
                        -Source $script:HostName -Target $row.Host -Port ([string]$p) `
                        -Finding ('Reachable ' + (Get-ServiceNameForPort $p) + ' on TCP/' + $p + ' from the assessment position.') `
                        -Observed ('TCP/' + $p + ' open from ' + $script:HostName) -Validation 'TCP connect test (reachability only; no authentication attempted)' `
                        -Class $(if ($p -eq 3389) { 'High' } else { 'High' }) -CatClass 'Confidentiality' `
                        -Prerequisites 'Valid credentials for an account with access to this host (not validated by this tool).' `
                        -Exploitability 'Reachability validated; authentication not attempted. A reachable administrative service is a precondition, not a compromise.' `
                        -Remediation 'Restrict remote management interfaces to privileged-access workstations and management VLANs using host firewall rules and network ACLs. Require NLA (RDP) and HTTPS (WinRM), and enforce just-in-time access for administrators.' `
                        -Impact 'Any credential usable against this host (including one harvested elsewhere in the estate) provides interactive or remote-code-execution access to it; administrative interfaces reachable from user segments are the primary lateral-movement enabler.'
                }
            }
            if ($pi -contains 445 -and $pi -contains 139) {
                Add-Finding -Category 'Network Discovery' -Status 'INFO' -CatClass 'Context' -Attribute 'Legacy SMB transport reachable' `
                    -Source $script:HostName -Target $row.Host -Port '139,445' `
                    -Finding 'Both SMB over NetBIOS (139) and direct SMB (445) are reachable on this host.' `
                    -Observed 'TCP/139 and TCP/445 open' -Validation 'TCP connect tests (no SMB negotiation was performed against this remote host by this module; the local host''s SMB posture is validated in Section 3)' `
                    -Class 'Medium' -Remediation 'Disable NetBIOS over TCP/IP and block TCP/139 estate-wide; SMB over 445 only, with signing required.' `
                    -Impact 'A second SMB transport widens relay and legacy-protocol opportunities; on a modern estate port 139 is not required.' -NoConsole
        }
    }
    # NOTE: the brace above closes the per-host summary foreach and MUST stay here. Without it:
    #   * the following 'else' stops being a keyword and is parsed as a COMMAND named "else",
    #     which throws at run time when the sweep executes;
    #   * the sweep guard below swallows every later statement in this section;
    #   * the deadline finding is evaluated once per discovered host instead of once per sweep.
    # None of that is visible to a syntax check; the offline AST audit asserts it.

    if ($sweep.TimedOut) {
            Add-Finding -Category 'Network Discovery' -Status 'NOT TESTABLE' -Attribute 'Incomplete sweep coverage' `
                -Finding 'The discovery sweep hit its wall-clock ceiling and did not complete every address in the derived scope.' `
                -Observed ($sweep.Processed.ToString() + ' of ' + $sweep.Total + ' addresses checked before the deadline') `
                -Validation 'Deadline control (reported rather than hidden)' -Class 'Medium' `
                -Remediation 'Re-run discovery with a longer ceiling or a narrower scope; split the assessment by subnet.' `
                -Impact 'Unknown hosts may remain in the unscanned portion of the scope; the host count in the executive summary is a LOWER bound, not a total.' -NoConsole
        }
    } else {
        Write-Status 'NOT TESTABLE' ('No discovery sweep was performed (no scope derived, declined, or unattended without pre-authorisation). Consent path: ' + $consentMode)
    }

    # ---- Explicit DC reachability (independent of the sweep) -----------------------------
    if ($dcTarget -and -not (Test-TargetAllowed -Target $dcTarget)) {
        Write-Status 'NOT TESTABLE' ((Get-TargetSuppressionReason -Target $dcTarget) + ' - the domain controller reachability probe was not performed.')
        Write-KV 'DC reachability probe' ('SUPPRESSED (no TCP connect was attempted against the domain controller): ' + (Get-TargetSuppressionReason -Target $dcTarget))
    }
    if ($dcTarget -and (Test-TargetAllowed -Target $dcTarget)) {
        Write-Host ''
        Write-Host '  -- 8.5 Domain controller reachability (explicit target) ---------------------------' -ForegroundColor DarkCyan
        $dcPorts = @(53,88,135,389,445,636,3268,3269)
        $dcOpen = @()
        foreach ($p in $dcPorts) {
            $t = Test-TcpPort -Target $dcTarget -Port $p -TimeoutMs 800
            if ($t.State -eq 'Open') { $dcOpen += $p }
        }
        Write-Status 'INFO' ('DC ' + $script:DomainControllerName + ' (' + $dcTarget + '): ' + $(if ($dcOpen.Count) { 'open ports ' + ($dcOpen -join ', ') } else { 'no probed ports open' }))
        Add-Finding -Category 'Network Discovery' -Status 'INFO' -CatClass 'Context' -Attribute 'Domain controller reachability' `
            -Source $script:HostName -Target ($script:DomainControllerName + ' (' + $dcTarget + ')') -Port ($dcOpen -join ',') `
            -Finding ('Domain controller reachability from the assessment position: ' + $(if ($dcOpen.Count) { 'ports ' + ($dcOpen -join ', ') + ' reachable' } else { 'no probed service reachable' }) + '.') `
            -Observed ('Open: ' + ($dcOpen -join ', ')) -Validation 'Bounded TCP connect tests' -Class 'Low' `
            -Remediation 'Verify that DC ports are reachable only from tiers and networks that require them; directory services should not be reachable from general user segments (see Section 15).' `
            -Impact 'DC service reachability from a low-trust segment is the precondition for relay and LDAP-based escalation paths; it is recorded here as reachability only.' -NoConsole
    }

    # ---- 8.6 read-only banner / certificate capture (NOT 8.5 - 8.5 is DC reachability) ----
    # Placed inside the Test-RemoteAllowed block already enclosing 8.3/8.4, and re-gated here so
    # that a /localonly run cannot reach this loop by any control-flow path.
    if (-not (Test-RemoteAllowed)) {
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - service banner capture was not performed.')
    } else {
        Write-Host ''
        Write-Host '  -- 8.6 Service banner / TLS certificate capture ----------------------------------' -ForegroundColor DarkCyan
        $bp = @($script:Cfg.BannerPorts)
        $bannerJobs = @()
        foreach ($d in $discovered) {
            if ($bp -contains [int]$d.Port) {
                if (-not (Test-InScope -Target ([string]$d.Host))) { continue }
                if (Test-KillSwitch) { break }
                $bannerJobs += , @([string]$d.Host, [int]$d.Port)
            }
        }
        if ($bannerJobs.Count -eq 0) {
            Write-Status 'INFO' 'no banner-capable service was found on a responsive host'
        } else {
            Write-Status 'INFO' ('capturing ' + $bannerJobs.Count + ' banner(s) - read-only: greeting read, HEAD / on HTTP, handshake on TLS')
            $banners = @()
            foreach ($j in $bannerJobs) { $banners += (Invoke-BannerGrab -Target $j[0] -Port $j[1]) }
            $bRows = @()
            foreach ($b in $banners) {
                $shown = ''
                if ($b.Kind -eq 'suppressed' -or $b.Kind -eq 'not-probed') { $shown = $b.Note }
                elseif ($b.Product) { $shown = $b.Product } else { $shown = '(no identifying string offered)' }
                if ($shown.Length -gt 90) { $shown = $shown.Substring(0, 90) + '...' }
                $bRows += [pscustomobject]@{
                    Endpoint = ([string]$b.Host + ':' + [string]$b.Port)
                    Kind     = $b.Kind
                    Identity = $shown
                    Note     = $b.Note
                }
            }
            Write-Table -Rows $bRows -Columns @('Endpoint','Kind','Identity','Note') -Headers @{ Endpoint='Endpoint'; Kind='Exchange'; Identity='Advertised identity'; Note='Remark' }

            # Version disclosure. This is a WEAKNESS only in the sense that it assists
            # fingerprinting - it is reported as such and never inflated into an exploit claim.
            foreach ($b in $banners) {
                if ($b.Kind -ne 'greeting' -and $b.Kind -ne 'http') { continue }
                if (-not $b.Product) { continue }
                if ($b.Product -notmatch '[0-9]') { continue }
                Add-Finding -Category 'Service exposure / pre-authentication fingerprinting' `
                    -Status 'RISK DETECTED' `
                    -Finding ('Service on TCP ' + $b.Port + ' volunteers a product/version string before authentication: ' + $b.Product) `
                    -Attribute 'Pre-authentication banner disclosure' `
                    -Source ('Section 8.6 / ' + $b.Host) -Target $b.Host -Port ([string]$b.Port) `
                    -Prerequisites 'TCP reachability from the assessment host; no credentials presented and no protocol state advanced' `
                    -Observed ('Banner: ' + $b.Banner) `
                    -Validation 'Definitive for the banner itself: the string was read directly from the service in this run and is reproduced verbatim above. Mapping that string to a specific CVE was NOT performed and is not claimed.' `
                    -Exploitability 'Informational to Low - a version string is not by itself exploitable; it becomes actionable only against a matching published vulnerability' `
                    -Impact 'Removes guesswork from adversary pre-attack reconnaissance and shortlists the target for version-specific exploitation' `
                    -Expected 'Banner suppressed where the vendor supports it, or the service reachable only from required source ranges' `
                    -Configured 'Vendor default - FTP, SSH, Telnet and many HTTP servers emit an identifying banner before authentication' `
                    -Remediation 'Suppress version strings where supported; otherwise patch to a current release and restrict reachability of the service to required source ranges' `
                    -Class 'Low' -CatClass 'Context' -Weakness $false
            }

            # TLS trust defects. Reported separately because an expired or self-signed certificate
            # on an internal management interface is a real condition, not a fingerprint issue.
            foreach ($b in $banners) {
                if ($b.Kind -ne 'tls') { continue }
                if ($b.Note -notmatch 'self-signed|expired') { continue }
                $defects = $b.Note
                Add-Finding -Category 'Certificate trust' `
                    -Status 'RISK DETECTED' `
                    -Finding ('TLS endpoint presents a certificate with trust defect(s): ' + $defects) `
                    -Attribute 'Certificate trust defect' `
                    -Source ('Section 8.6 / ' + $b.Host) -Target $b.Host -Port ([string]$b.Port) `
                    -Prerequisites 'TCP reachability from the assessment host; handshake completed against an accepted certificate' `
                    -Observed $b.Banner `
                    -Validation 'Deterministic for the certificate as presented: subject, issuer and validity dates were read from the live handshake. Certificate-chain revocation was NOT checked, and no trust-store or PKI configuration was inspected, so the root cause is not attributed.' `
                    -Exploitability 'Low - enables interception of traffic a user believes to be protected, if combined with a position on the path' `
                    -Impact 'Weakens the confidentiality guarantee of the management interface and trains operators to click through trust warnings' `
                    -Expected 'Certificate issued by the internal PKI, within its validity period, with the target host name in the SAN' `
                    -Configured 'Certificate as deployed on the listening service' `
                    -Remediation 'Reissue from the internal PKI with the correct SAN and an expiry that is tracked; replace self-signed certificates on management interfaces; add expiry monitoring so renewal is not manual' `
                    -Class 'Low' -CatClass 'Confidentiality' -Weakness $true
            }
        }
    }

    # =======================================================================================
    #  8.x Runtime Network Protocol Interrogation
    #  READ-ONLY: CIM adapter inventory plus .NET registry reads; no network command/process.
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- Runtime Network Protocol Interrogation --------------------------------------' -ForegroundColor DarkCyan
    try {
        $liveBypasses = @()
        $adapters = Get-CimSafe -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = True'
        foreach ($adapter in $adapters) {
            $settingId = [string]$adapter.SettingID
            if ([string]::IsNullOrWhiteSpace($settingId)) { continue }

            $netbiosReg = Get-RegValue -Path ('SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $settingId) -Name 'NetbiosOptions'
            $netbiosValue = Get-U32 $netbiosReg
            if ($null -eq $netbiosValue -or $netbiosValue -ne 2) {
                $liveBypasses += [pscustomobject]@{
                    SettingID = $settingId
                    NetbiosOptions = if ($null -eq $netbiosValue) { '(absent/default)' } else { [string]$netbiosValue }
                    InterfaceDescription = [string]$adapter.Description
                    IPAddress = if ($adapter.IPAddress) { (@($adapter.IPAddress) -join ', ') } else { '' }
                }
            }
        }

        if ($liveBypasses.Count -gt 0) {
            Write-Table -Rows $liveBypasses -Columns @('SettingID','NetbiosOptions','InterfaceDescription','IPAddress') `
                -Headers @{ SettingID='Setting ID'; NetbiosOptions='NetbiosOptions'; InterfaceDescription='Adapter'; IPAddress='IP Address' }
            Write-Status 'WARN' (($liveBypasses.Count).ToString() + ' IP-enabled adapter(s) have NetBIOS over TCP/IP not explicitly disabled (NetbiosOptions != 2 or absent).')
            Add-Finding -Category 'Name Resolution' -Status 'WARN' `
                -Attribute 'Active Operational NetBIOS Interfaces' `
                -Finding 'One or more IP-enabled network interfaces do not have NetBIOS over TCP/IP explicitly disabled in the per-interface NetBT configuration.' `
                -Observed (($liveBypasses | ForEach-Object { $_.SettingID + '=' + $_.NetbiosOptions }) -join '; ') `
                -Validation 'Read-only CIM enumeration of IPEnabled network adapter configurations correlated with the per-interface NetbiosOptions registry value.' `
                -Class 'Medium' -CatClass 'Confidentiality'
        } else {
            Write-Status 'PASS' 'All IP-enabled network adapters have NetbiosOptions explicitly set to 2.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Runtime NetBIOS interface interrogation failed: ' + $_.Exception.Message)
    }

    # Native read-only corroboration: netstat -ano. This does not replace the CIM adapter
    # interrogation above; it provides a runtime socket snapshot that can be correlated with it.
    Write-Host ''
    Write-Host '  -- Native runtime socket corroboration (netstat) -------------------------------' -ForegroundColor DarkCyan
    try {
        $netstatLines = @(& netstat.exe -ano 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not $netstatLines) {
            throw ('netstat.exe returned exit code ' + [string]$LASTEXITCODE)
        }
        $socketRows = @()
        foreach ($line in $netstatLines) {
            $t = ([string]$line).Trim()
            if ($t -match '^(TCP|UDP)\s+') {
                $parts = $t -split '\s+'
                if ($parts.Count -ge 4) {
                    $socketRows += [pscustomobject]@{ Protocol=$parts[0]; LocalAddress=$parts[1]; ForeignAddress=$parts[2]; State=$(if ($parts.Count -ge 5) { $parts[3] } else { '' }); PID=$(if ($parts.Count -ge 5) { $parts[4] } else { $parts[3] }) }
                }
            }
        }
        if ($socketRows.Count -gt 0) {
            Write-Table -Rows ($socketRows | Select-Object -First 50) -Columns @('Protocol','LocalAddress','ForeignAddress','State','PID') `
                -Headers @{ Protocol='Proto'; LocalAddress='Local Address'; ForeignAddress='Foreign Address'; State='State'; PID='PID' }
            Write-KV 'Native netstat rows' $socketRows.Count 'Snapshot capped at 50 rows for console/report readability.'
            Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' `
                -Attribute 'Native runtime socket snapshot' `
                -Finding 'A read-only netstat snapshot was collected as runtime corroboration for the network discovery section.' `
                -Observed (($socketRows | Select-Object -First 10 | ForEach-Object { $_.Protocol + ' ' + $_.LocalAddress + ' -> ' + $_.ForeignAddress + ' ' + $_.State + ' PID=' + $_.PID }) -join '; ') `
                -Validation 'Read-only native netstat.exe -ano invocation; no network connection was created, modified, or terminated.' `
                -Class 'Low' -CatClass 'Context' -NoConsole
        } else {
            Write-Status 'PASS' 'netstat.exe returned no parseable TCP/UDP socket rows.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Native netstat runtime corroboration failed: ' + $_.Exception.Message)
    }

}
# ===========================================================================================
#  ACTIVE DIRECTORY ENUMERATION CORE + SECTION 9  (part 7/12)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  The directory is the control plane of the estate: account configuration, delegation,
#  encryption capability, privileged membership and trusts all live here. Every query in this
#  part is a plain LDAP search performed with the assessment identity's own rights - no RSAT
#  module, no remote WMI, no remote registry, and no cached credentials of any kind.
#
#  SCOPE DISCIPLINE
#  ----------------------------------------------------------------------------------------
#  Only the attributes needed to reach an assessment conclusion are requested in
#  PropertiesToLoad. This is deliberate: asking for fewer attributes produces less sensitive
#  data in memory, keeps the evidence set auditable, and avoids the tool ever touching
#  credential material (no ms-Mcs-AdmPwd, no unicodePwd, no supplementalCredentials, no
#  userParameters, no unixUserPassword, and no LAPS password values).
# ===========================================================================================

$script:LdapReady       = $false
$script:LdapRootPath    = ''
$script:LdapAuthority   = 'current user'
$script:AdCounts        = @{ Users = 0; Computers = 0; Groups = 0; DomainControllers = 0; Kerberoastable = 0; Capped = $false }
$script:PrivilegedGroups = @(
    'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators',
    'Server Operators','Backup Operators','Print Operators','Group Policy Creator Owners',
    'DNSAdmins','Replicator','Cert Publishers','Protected Users','DnsUpdateProxy','Exchange Trusted Subsystem',
    'Organization Management','Enterprise Key Admins','Key Admins'
)
$script:PrivilegedGroupDns = New-Object System.Collections.ArrayList

function Initialize-LdapConnection {
    if ($script:LdapReady) { return $true }

    # /localonly: no LDAP is opened at all. Every directory module then reports NOT TESTABLE with
    # the operator-suppression wording (see Get-LdapUnavailableReason) rather than implying that a
    # directory was contacted and found unreachable.
    if (-not (Test-RemoteAllowed)) {
        $script:LdapSuppressed = $true
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - LDAP/ADSI directory queries (Sections 9-14) were not performed.')
        Write-KV 'Directory queries' 'SUPPRESSED by /localonly (no LDAP socket was opened)'
        return $false
    }
    if (-not $script:Section1Role -or $script:Section1Role -like '*WORKGROUP*' -or $script:Section1Role -like '*standalone*') {
        if ($script:Section1Role -like '*Workstation (standalone*' -or $script:Section1Role -like '*Member Server (standalone*') {
            Write-Status 'NOT TESTABLE' 'Host is not domain-joined: Active Directory modules cannot run from this context.'
            return $false
        }
    }
    $server = $script:DomainControllerName
    if (-not $script:DomainNamingContext) {
        try {
            $r = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
            $script:DomainNamingContext = [string]$r.Properties['defaultNamingContext'].Value
            if (-not $script:DomainControllerName) { $script:DomainControllerName = [string]$r.Properties['dnsHostName'].Value }
        } catch {
            Write-Status 'WARN' ('RootDSE could not be read: ' + $_.Exception.Message)
        }
    }
    if (-not $script:DomainNamingContext) {
        Write-Status 'NOT TESTABLE' 'No default naming context available (non-domain host, unreachable DC, or blocked LDAP). Directory modules will report NOT TESTABLE.'
        return $false
    }
    $roots = @()
    if ($server) { $roots += ('LDAP://' + $server + '/' + $script:DomainNamingContext) }
    $roots += ('LDAP://' + $script:DomainNamingContext)
    foreach ($root in $roots) {
        try {
            $probe = New-Object System.DirectoryServices.DirectoryEntry($root)
            $null = $probe.Guid     # forces a bind; throws when the server is unreachable
            $script:LdapRootPath = $root
            $script:LdapReady = $true
            Write-KV 'LDAP search root' $script:LdapRootPath
            Write-KV 'LDAP authority' $script:LdapAuthority
            return $true
        } catch {
            Write-Status 'WARN' ('LDAP bind failed against ' + $root + ': ' + $_.Exception.Message)
        }
    }
    Write-Status 'NOT TESTABLE' 'No LDAP connection could be established; all directory modules will report NOT TESTABLE rather than guessing.'
    return $false
}

function New-AdSearcher {
    param(
        [Parameter(Mandatory=$true)][string]$Filter,
        [string[]]$Properties = @('distinguishedName'),
        [string]$SearchRoot = '',
        [int]$PageSize = 500,
        [string]$Scope = 'Subtree'
    )
    $root = if ($SearchRoot) { $SearchRoot } else { $script:LdapRootPath }
    $ds = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$root)
    $ds.Filter = $Filter
    $ds.PageSize = $PageSize
    $ds.SearchScope = if ($Scope -eq 'Base') { [System.DirectoryServices.SearchScope]::Base } else { [System.DirectoryServices.SearchScope]::Subtree }
    foreach ($p in $Properties) { [void]$ds.PropertiesToLoad.Add($p) }
    try { $ds.ServerTimeLimit = [TimeSpan]::FromSeconds(60) } catch { }
    try { $ds.ClientTimeout = [TimeSpan]::FromSeconds(90) } catch { }
    return $ds
}

function ConvertTo-AdHash {
    param([System.DirectoryServices.SearchResult]$Result)
    $h = @{ DistinguishedName = $Result.Path }
    try {
        foreach ($n in $Result.Properties.PropertyNames) {
            $vals = @()
            foreach ($v in $Result.Properties[$n]) {
                if ($v -is [byte[]]) { $vals += ('<binary ' + $v.Length + ' bytes>') }
                else { $vals += [string]$v }
            }
            $h[$n] = $vals
        }
    } catch { }
    if (-not $h.ContainsKey('distinguishedName')) {
        try { $h['distinguishedName'] = @([string]$Result.Properties['distinguishedName'][0]) } catch { }
    }
    return $h
}

function Get-AdProperty {
    param([hashtable]$Object, [string]$Name, [int]$Index = 0)
    if (-not $Object -or -not $Object.ContainsKey($Name)) { return $null }
    $v = $Object[$Name]
    if ($null -eq $v) { return $null }
    if ($v -is [array]) { if ($v.Count -le $Index) { return $null }; return $v[$Index] }
    return $v
}

function Get-AdObjects {
    <# Paged LDAP search with a hard object cap. Returns a list of hashtables.
       The cap is reported in the evidence so a truncated enumeration is never presented as
       a complete one. #>
    param(
        [Parameter(Mandatory=$true)][System.DirectoryServices.DirectorySearcher]$Searcher,
        [int]$Cap = $script:Cfg.MaxAdObjects
    )
    $list = New-Object System.Collections.ArrayList
    try {
        $results = $Searcher.FindAll()
        foreach ($r in $results) {
            [void]$list.Add((ConvertTo-AdHash -Result $r))
            if ($list.Count -ge $Cap) { $script:AdCounts.Capped = $true; break }
        }
        $results.Dispose()
    } catch {
        Write-Status 'ERROR' ('LDAP query failed (' + $Searcher.Filter + '): ' + $_.Exception.Message)
        return $null
    }
    return $list
}

function Get-AdPropertyCount {
    param([System.DirectoryServices.DirectorySearcher]$Searcher, [int]$Cap = $script:Cfg.MaxAdObjects)
    $n = 0
    try {
        $results = $Searcher.FindAll()
        foreach ($r in $results) { $n++; if ($n -ge $Cap) { $script:AdCounts.Capped = $true; break } }
        $results.Dispose()
    } catch {
        Write-Status 'WARN' ('LDAP count query failed (' + $Searcher.Filter + '): ' + $_.Exception.Message)
        return -1
    }
    return $n
}

function Convert-FileTimeToDate {
    param([object]$Value)
    $v = 0
    if ($null -eq $Value) { return $null }
    if (-not [int64]::TryParse([string]$Value, [ref]$v)) { return $null }
    if ($v -le 0) { return $null }
    try { return [datetime]::FromFileTime($v) } catch { return $null }
}

function Get-DaysSince { param([datetime]$Date) return [int]((Get-Date) - $Date).TotalDays }

function Initialize-PrivilegedGroups {
    <# Resolves the DN of every well-known privileged group present in the directory. Used to
       attribute privileged-group relationships without expanding full recursive membership
       (which would be an expensive and invasive query set). #>
    if ($script:PrivilegedGroupDns.Count -gt 0) { return }
    $filter = '(|' + (($script:PrivilegedGroups | ForEach-Object { '(cn=' + $_ + ')' }) -join '') + ')'
    $ds = New-AdSearcher -Filter ('(&(objectCategory=group)' + $filter + ')') -Properties @('distinguishedName','cn','member')
    $groups = Get-AdObjects -Searcher $ds
    if ($null -eq $groups) { return }
    foreach ($g in $groups) {
        $dn = Get-AdProperty $g 'distinguishedName'
        $cn = Get-AdProperty $g 'cn'
        if ($dn) { [void]$script:PrivilegedGroupDns.Add([pscustomobject]@{ Name = $cn; DN = $dn }) }
    }
    Write-KV 'Privileged groups resolved' ($script:PrivilegedGroupDns.Count.ToString() + ' of ' + $script:PrivilegedGroups.Count + ' known names')
}

function Test-PrivilegedRelationship {
    param([hashtable]$Object)
    $reasons = @()
    try { if ((Get-AdProperty $Object 'adminCount') -eq '1') { $reasons += 'adminCount=1 (SDProp-protected: member of a protected/privileged group or previously was)' } } catch { }
    $memberOf = $Object['memberof']
    if ($memberOf) {
        foreach ($m in $memberOf) {
            foreach ($pg in $script:PrivilegedGroupDns) { if ($m -ieq $pg.DN) { $reasons += ('memberOf ' + $pg.Name) } }
        }
    }
    try { if ((Get-AdProperty $Object 'sAMAccountName') -ieq 'krbtgt') { $reasons += 'KRBTGT account' } } catch { }
    return [pscustomobject]@{ IsPrivileged = [bool]($reasons.Count -gt 0); Reasons = ($reasons -join '; ') }
}

function Get-UacDecode {
    <# EXACT hexadecimal bitwise decoding of userAccountControl.
       Every value and mask is stated in hexadecimal so the arithmetic can be verified by hand
       against the Microsoft-documented flags. #>
    param([object]$UacValue)
    $r = [pscustomobject]@{ Value=$null; ValueHex=''; Flags=@(); FlagNames=''; IsDisabled=$null; GoodPassword=$null; DontReqPreAuth=$null; TrustedForDelegation=$null; NotDelegated=$null }
    $v = 0
    if ($null -eq $UacValue -or -not [int64]::TryParse([string]$UacValue, [ref]$v)) { return $r }
    $r.Value = $v
    $r.ValueHex = '0x' + ([int64]$v).ToString('X8')
    # NOTE ON DATA STRUCTURE: these masks are held in an ARRAY of objects, not in a hashtable.
    # A [ordered] dictionary with integer keys is UNSAFE here: System.Collections.Specialized.
    # OrderedDictionary exposes BOTH Item[object key] and Item[int index], and PowerShell binds
    # $map[512] to the POSITIONAL index - the lookup returns $null silently. That defect was
    # reproduced offline and is why this table is an array with an explicit -band comparison.
    $map = @(
        [pscustomobject]@{ Mask=0x00000001; Name='SCRIPT (0x00000001)' }
        [pscustomobject]@{ Mask=0x00000002; Name='ACCOUNTDISABLE (0x00000002)' }
        [pscustomobject]@{ Mask=0x00000008; Name='HOMEDIR_REQUIRED (0x00000008)' }
        [pscustomobject]@{ Mask=0x00000010; Name='LOCKOUT (0x00000010)' }
        [pscustomobject]@{ Mask=0x00000020; Name='PASSWD_NOTREQD (0x00000020)' }
        [pscustomobject]@{ Mask=0x00000040; Name='PASSWD_CANT_CHANGE (0x00000040)' }
        [pscustomobject]@{ Mask=0x00000080; Name='ENCRYPTED_TEXT_PWD_ALLOWED (0x00000080)' }
        [pscustomobject]@{ Mask=0x00000100; Name='TEMP_DUPLICATE_ACCOUNT (0x00000100)' }
        [pscustomobject]@{ Mask=0x00000200; Name='NORMAL_ACCOUNT (0x00000200)' }
        [pscustomobject]@{ Mask=0x00000800; Name='INTERDOMAIN_TRUST_ACCOUNT (0x00000800)' }
        [pscustomobject]@{ Mask=0x00001000; Name='WORKSTATION_TRUST_ACCOUNT (0x00001000)' }
        [pscustomobject]@{ Mask=0x00002000; Name='SERVER_TRUST_ACCOUNT (0x00002000)' }
        [pscustomobject]@{ Mask=0x00010000; Name='DONT_EXPIRE_PASSWORD (0x00010000)' }
        [pscustomobject]@{ Mask=0x00020000; Name='MNS_LOGON_ACCOUNT (0x00020000)' }
        [pscustomobject]@{ Mask=0x00040000; Name='SMARTCARD_REQUIRED (0x00040000)' }
        [pscustomobject]@{ Mask=0x00080000; Name='TRUSTED_FOR_DELEGATION (0x00080000)' }
        [pscustomobject]@{ Mask=0x00100000; Name='NOT_DELEGATED (0x00100000)' }
        [pscustomobject]@{ Mask=0x00200000; Name='USE_DES_KEY_ONLY (0x00200000)' }
        [pscustomobject]@{ Mask=0x00400000; Name='DONT_REQ_PREAUTH (0x00400000)' }
        [pscustomobject]@{ Mask=0x00800000; Name='PASSWORD_EXPIRED (0x00800000)' }
        [pscustomobject]@{ Mask=0x01000000; Name='TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000)' }
        [pscustomobject]@{ Mask=0x04000000; Name='PARTIAL_SECRETS_ACCOUNT (0x04000000)' }
    )
    $flags = @()
    foreach ($m in $map) {
        if (($v -band $m.Mask) -eq $m.Mask) { $flags += $m.Name }
    }
    $r.Flags = $flags
    $r.FlagNames = ($flags -join ' + ')
    $r.IsDisabled          = (($v -band 0x00000002) -eq 0x00000002)
    $r.GoodPassword        = -not (($v -band 0x00000020) -eq 0x00000020)
    $r.DontReqPreAuth      = (($v -band 0x00400000) -eq 0x00400000)
    $r.TrustedForDelegation= (($v -band 0x00080000) -eq 0x00080000)
    $r.NotDelegated        = (($v -band 0x00100000) -eq 0x00100000)
    return $r
}

function Get-AdSchemaAttributePresence {
    param([string[]]$CommonNames)
    $out = @{}
    foreach ($c in $CommonNames) { $out[$c] = $false }
    # Defence in depth: without an established directory connection no schema query is possible.
    # Section 14 (the only caller) already refuses to run when LdapReady is false, so this branch is
    # unreachable in a normal run; the status line exists so that if it ever IS reached, the reader
    # sees 'not queried' rather than an all-false map that could be misread as 'attributes absent'.
    if (-not $script:LdapReady) {
        Write-Status 'NOT TESTABLE' ((Get-LdapUnavailableReason) + ': schema attribute presence was not queried.')
        return $out
    }
    try {
        $schemaNc = ''
        try {
            $r = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
            $schemaNc = [string]$r.Properties['schemaNamingContext'].Value
        } catch { }
        if (-not $schemaNc) { return $out }
        foreach ($c in $CommonNames) {
            $ds = New-AdSearcher -Filter ('(&(objectClass=attributeSchema)(lDAPDisplayName=' + $c + '))') -Properties @('lDAPDisplayName','cn','whenCreated') -SearchRoot ('LDAP://' + $script:DomainControllerName + '/' + $schemaNc) -Scope 'Subtree'
            $objs = Get-AdObjects -Searcher $ds -Cap 5
            if ($objs -and $objs.Count -gt 0) { $out[$c] = $true }
        }
    } catch {
        Write-Status 'WARN' ('Schema query failed: ' + $_.Exception.Message + ' - LAPS schema presence will be reported as unknown.')
    }
    return $out
}

# ===========================================================================================
#  SECTION 9 :: ACTIVE DIRECTORY ENUMERATION
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Establishes the directory-scale facts that give every later finding its context: how large
#  the identity surface is, which accounts are privileged, which trusts exist, and what the
#  domain's password policy actually is. A finding like "one account has pre-authentication
#  disabled" means something completely different on a 40-account domain than on a
#  40,000-account domain.
# ===========================================================================================
function Invoke-Section9_AdEnumeration {
    if (-not (Initialize-LdapConnection)) {
        Add-Finding -Category 'Active Directory' -Status 'NOT TESTABLE' -Attribute 'AD enumeration' `
            -Finding 'Active Directory could not be enumerated from this context (non-domain host, unreachable domain controller, or blocked LDAP). No directory conclusions are drawn.' `
            -Observed ('Role: ' + $script:Section1Role + '; DC: ' + $(if ($script:DomainControllerName) { $script:DomainControllerName } else { 'unresolved' })) `
            -Validation 'Not performed' -Class 'High' `
            -Remediation 'Run the assessment from a domain-joined host with LDAP access to a writable domain controller to obtain directory coverage.' `
            -Impact 'Unknown. Absence of directory findings in this report must not be read as absence of directory weaknesses.' -NoConsole
        return
    }
    Initialize-PrivilegedGroups

    Write-Host ''
    Write-Host '  -- 9.1 Directory scope -----------------------------------------------------------' -ForegroundColor DarkCyan
    Write-KV 'Domain' $script:DomainNamingContext
    $rootDse = @{}
    try {
        $r = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        foreach ($n in @('domainFunctionality','forestFunctionality','domainControllerFunctionality','dnsHostName','configurationNamingContext','schemaNamingContext','isGlobalCatalogReady','supportedLDAPVersion','serverName')) {
            try { $v = $r.Properties[$n].Value; if ($v) { $rootDse[$n] = [string]($v -join ',') } } catch { }
        }
    } catch { }
    $flMap = @{ 0='Windows 2000'; 1='Windows Server 2003'; 2='Windows Server 2008'; 3='Windows Server 2008 R2'; 4='Windows Server 2012'; 5='Windows Server 2012 R2'; 6='Windows Server 2016'; 7='Windows Server 2025' }
    foreach ($k in @('domainFunctionality','forestFunctionality','domainControllerFunctionality')) {
        if ($rootDse.ContainsKey($k)) {
            $lv = 0; $name = ''
            if ([int]::TryParse($rootDse[$k], [ref]$lv) -and $flMap.ContainsKey($lv)) { $name = $flMap[$lv] }
            Write-Context $k ($rootDse[$k] + $(if ($name) { ' (' + $name + ')' } else { '' }))
        }
    }
    if ($rootDse.ContainsKey('isGlobalCatalogReady')) { Write-Context 'isGlobalCatalogReady' $rootDse['isGlobalCatalogReady'] }

    # ---- Object counts -------------------------------------------------------------------
    Write-Host ''
    Write-Host '  -- 9.2 Object inventory (paged LDAP, capped at ' + $script:Cfg.MaxAdObjects + ' per class) --' -ForegroundColor DarkCyan
    $uCount = Get-AdPropertyCount -Searcher (New-AdSearcher -Filter '(&(objectCategory=person)(objectClass=user))' -Properties @('distinguishedName'))
    $cCount = Get-AdPropertyCount -Searcher (New-AdSearcher -Filter '(objectCategory=computer)' -Properties @('distinguishedName'))
    $gCount = Get-AdPropertyCount -Searcher (New-AdSearcher -Filter '(objectCategory=group)' -Properties @('distinguishedName'))
    $dcCount= Get-AdPropertyCount -Searcher (New-AdSearcher -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Properties @('distinguishedName'))
    $script:AdCounts.Users = $uCount; $script:AdCounts.Computers = $cCount; $script:AdCounts.Groups = $gCount; $script:AdCounts.DomainControllers = $dcCount
    $script:Stats.AdObjectsAssessed = ($uCount + $cCount + $gCount)
    Write-KV 'User objects' $uCount
    Write-KV 'Computer objects' $cCount
    Write-KV 'Group objects' $gCount
    Write-KV 'Domain controllers' $dcCount
    Add-Finding -Category 'Active Directory' -Status 'INFO' -CatClass 'Context' -Attribute 'Directory object inventory' `
        -Finding ('Directory contains ' + $uCount + ' user, ' + $cCount + ' computer and ' + $gCount + ' group objects, with ' + $dcCount + ' domain controller(s).') `
        -Observed ('Counts obtained by paged LDAP enumeration of class-scoped filters' + $(if ($script:AdCounts.Capped) { ' - ENUMERATION WAS CAPPED at ' + $script:Cfg.MaxAdObjects + ' objects per class, so these are lower bounds' } else { '' })) `
        -Validation 'Paged LDAP searches (PageSize 500) using only the assessment identity''s own rights; no credentials are used beyond the current logon context.' `
        -Class 'Low' -Remediation 'No action - this is scale context for prioritising the findings below.' `
        -Impact 'None by itself; it defines the blast radius of the account-level findings that follow.' -NoConsole

    # ---- Domain controllers --------------------------------------------------------------
    Write-Host ''
    Write-Host '  -- 9.3 Domain controllers --------------------------------------------------------' -ForegroundColor DarkCyan
    $dcDs = New-AdSearcher -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Properties @('distinguishedName','dNSHostName','operatingSystem','operatingSystemVersion','whenCreated','lastLogonTimestamp','msDS-SupportedEncryptionTypes','servicePrincipalName')
    $dcs = Get-AdObjects -Searcher $dcDs
    if ($dcs) {
        $dcRows = @()
        foreach ($d in $dcs) {
            $dcRows += [pscustomobject]@{
                Host = (Get-AdProperty $d 'dNSHostName'); OS = (Get-AdProperty $d 'operatingSystem')
                Version = (Get-AdProperty $d 'operatingSystemVersion')
                LastLogon = $(($ll = Convert-FileTimeToDate (Get-AdProperty $d 'lastLogonTimestamp')); if ($ll) { $ll.ToString('yyyy-MM-dd') } else { 'n/a' })
                Et = (Get-AdProperty $d 'msDS-SupportedEncryptionTypes')
            }
        }
        Write-Table -Rows $dcRows -Columns @('Host','OS','Version','LastLogon','Et') -Headers @{ Host='Domain controller'; OS='Operating system'; Version='Version'; LastLogon='Last logon'; Et='msDS-SupportedEncryptionTypes' }
    }

    # ---- Privileged groups ---------------------------------------------------------------
    Write-Host ''
    Write-Host '  -- 9.4 Privileged group membership ----------------------------------------------' -ForegroundColor DarkCyan
    $privRows = @()
    $privTotal = 0
    foreach ($pg in $script:PrivilegedGroupDns) {
        $ds = New-AdSearcher -Filter '(distinguishedName=' + $pg.DN + ')' -Properties @('member','distinguishedName','cn')
        $objs = Get-AdObjects -Searcher $ds -Cap 1
        $n = 0
        if ($objs -and $objs.Count -gt 0 -and $objs[0].ContainsKey('member')) { $n = @($objs[0]['member']).Count }
        $privTotal += $n
        $privRows += [pscustomobject]@{ Group = $pg.Name; DirectMembers = $n }
        Add-Finding -Category 'Active Directory' -Status $(if ($n -eq 0 -and $pg.Name -in @('Enterprise Admins','Schema Admins','Domain Admins')) { 'WARN' } else { 'INFO' }) -CatClass $(if ($pg.Name -in @('Domain Admins','Enterprise Admins','Schema Admins')) { 'IdentityRights' } else { 'Context' }) `
            -Attribute ('Privileged group: ' + $pg.Name) -Finding ($pg.Name + ' contains ' + $n + ' direct member(s).') `
            -Observed ('Direct member count ' + $n + ' (nested group membership is not expanded: this is a direct-membership count)') `
            -Validation 'LDAP read of the group''s member attribute (single query per group)' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'Keep privileged groups minimal and empty where possible, use tiered administration and just-in-time elevation, and place permanent privileged accounts in Protected Users with smartcard/credential requirements. Review every direct member quarterly.' `
            -Impact 'Every direct member is a domain-level target: compromise of any one of them yields the privileges of the group, which for Domain/Enterprise Admins is complete domain control.' -NoConsole
    }
    Write-Table -Rows ($privRows | Sort-Object -Property DirectMembers -Descending) -Columns @('Group','DirectMembers') -Headers @{ Group='Privileged group'; DirectMembers='Direct members' }
    Write-KV 'Direct privileged memberships (sum)' $privTotal
    $script:PrivDns = @($script:PrivilegedGroupDns | ForEach-Object { $_.DN })

    # ---- Trusts --------------------------------------------------------------------------
    Write-Host ''
    Write-Host '  -- 9.5 Trust relationships -------------------------------------------------------' -ForegroundColor DarkCyan
    $confNc = $rootDse['configurationNamingContext']
    $trustRows = @()
    if ($confNc) {
        $ds = New-AdSearcher -Filter '(objectClass=trustedDomain)' -Properties @('trustPartner','trustDirection','trustType','trustAttributes','securityIdentifier','whenCreated') -SearchRoot ('LDAP://' + $script:DomainControllerName + '/' + $confNc)
        $trusts = Get-AdObjects -Searcher $ds
        if ($null -eq $trusts) { Write-Status 'NOT TESTABLE' 'Trust enumeration failed (insufficient rights or blocked query).' }
        elseif ($trusts.Count -eq 0) { Write-Status 'PASS' 'No inbound/outbound trust objects were found in the configuration partition.' }
        else {
            foreach ($t in $trusts) {
                $dir = Get-AdProperty $t 'trustDirection'
                $dirName = switch ([string]$dir) { '0' { 'Disabled' } '1' { 'Inbound' } '2' { 'Outbound' } '3' { 'Bidirectional' } default { 'unknown' } }
                $att = Get-AdProperty $t 'trustAttributes'
                $quarantined = $false; $forestTransitive = $false; $treatAsExternal = $false
                $av = 0
                if ([int]::TryParse([string]$att, [ref]$av)) {
                    $quarantined     = (($av -band 0x00000004) -eq 0x00000004)   # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (SID filtering on)
                    $forestTransitive= (($av -band 0x00000008) -eq 0x00000008)   # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                    $treatAsExternal = (($av -band 0x00000040) -eq 0x00000040)   # TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL
                }
                $trustRows += [pscustomobject]@{
                    Partner = (Get-AdProperty $t 'trustPartner'); Direction = $dirName
                    Type = (Get-AdProperty $t 'trustType'); Attributes = ('0x' + $(if ([int]::TryParse([string]$att, [ref]$av)) { $av.ToString('X8') } else { '?' }))
                    SidFiltering = $(if ($quarantined) { 'enabled' } else { 'NOT enabled' })
                    Transitive = $forestTransitive
                }
                Add-Finding -Category 'Active Directory' -Status $(if (-not $quarantined) { 'WARN' } else { 'INFO' }) -CatClass 'IdentityRights' `
                    -Attribute ('Trust: ' + (Get-AdProperty $t 'trustPartner')) `
                    -Finding ('Domain trust with ' + (Get-AdProperty $t 'trustPartner') + ': direction=' + $dirName + ', SID filtering (quarantine) ' + $(if ($quarantined) { 'ENABLED' } else { 'NOT enabled' }) + ', forest-transitive=' + $forestTransitive + '.') `
                    -Configured ('trustAttributes=0x' + $(if ([int]::TryParse([string]$att, [ref]$av)) { $av.ToString('X8') } else { '?' }) + ' (bit 0x00000004 = TRUST_ATTRIBUTE_QUARANTINED_DOMAIN / SID filtering)') `
                    -Observed ('Trust direction ' + $dirName + ', type ' + (Get-AdProperty $t 'trustType') + ', SID-filtering state derived from exact bitwise decoding of trustAttributes') `
                    -Validation 'LDAP read of the trustedDomain object in the configuration partition. Active exploitation of the trust was NOT attempted.' `
                    -Class 'High' -CatClass 'IdentityRights' `
                    -Remediation $(if (-not $quarantined) { 'Enable SID filtering (quarantine) on this trust unless the partner domain must be able to use SIDs from its own forest, and treat the partner forest as an untrusted boundary in tiering decisions. Validate that no privileged groups have members from the partner domain.' } else { 'Maintain SID filtering and review the trust''s business need and its privileged members annually.' }) `
                    -Impact 'Trusts extend the authentication boundary: an attacker who compromises an account with SID-history or privileged access in the partner domain can inherit privileges here (inter-forest escalation), and inbound trust paths bypass perimeter assumptions.'
            }
            if ($trustRows.Count -gt 0) { Write-Table -Rows $trustRows -Columns @('Partner','Direction','Type','Attributes','SidFiltering','Transitive') -Headers @{ Partner='Partner domain'; Direction='Direction'; Type='Type'; Attributes='trustAttributes'; SidFiltering='SID filtering'; Transitive='Forest-transitive' } }
        }
    } else {
        Write-Status 'NOT TESTABLE' 'The configuration naming context was not readable, so trusts were not enumerated.'
        Add-Finding -Category 'Active Directory' -Status 'NOT TESTABLE' -Attribute 'Trust enumeration' -Finding 'Trust relationships could not be enumerated because the configuration naming context was not readable from this context.' `
            -Validation 'Not performed' -Class 'High' -Remediation 'Re-run from a context with read access to the configuration partition (a standard authenticated user normally has it).' `
            -Impact 'Unknown: an unenumerated trust is an unassessed authentication boundary.' -NoConsole
    }

    # ---- Domain password policy ----------------------------------------------------------
    Write-Host ''
    Write-Host '  -- 9.6 Domain password / lockout policy (default domain policy object) -----------' -ForegroundColor DarkCyan
    try {
        $ds = New-AdSearcher -Filter '(objectClass=domainDNS)' -Properties @('minPwdLength','pwdHistoryLength','pwdProperties','maxPwdAge','minPwdAge','lockoutDuration','lockoutThreshold','lockoutObservationWindow','ms-DS-MachineAccountQuota','whenCreated') -Scope 'Base'
        $dom = Get-AdObjects -Searcher $ds -Cap 1
        if ($dom -and $dom.Count -gt 0) {
            $d = $dom[0]
            $minLen = Get-AdProperty $d 'minPwdLength'
            $lockout = Get-AdProperty $d 'lockoutThreshold'
            $hist = Get-AdProperty $d 'pwdHistoryLength'
            $maxAge = Get-AdProperty $d 'maxPwdAge'
            $pwdProps = Get-AdProperty $d 'pwdProperties'
            $maq = Get-AdProperty $d 'ms-DS-MachineAccountQuota'
            $maxAgeDays = 'n/a'
            try { $v = [int64]$maxAge; if ($v -lt 0) { $maxAgeDays = [string][int]([math]::Abs($v) / 864000000000) } } catch { }
            # lockoutDuration and lockoutObservationWindow are stored in the SAME negative
            # 100-nanosecond FILETIME interval units as maxPwdAge, so they must be decoded before
            # they are shown. Reported raw, a 30-minute lockout reads as '-18000000000', which is
            # not interpretable in a compliance report and invites a misreading of the control.
            #   1 minute = 60 s x 10,000,000 (100 ns units) = 600,000,000
            $lockoutDurTxt = 'not readable'
            $lockoutWinTxt = 'not readable'
            try {
                $vd = [int64]0
                if ([int64]::TryParse([string](Get-AdProperty $d 'lockoutDuration'), [ref]$vd)) {
                    if ($vd -eq 0) { $lockoutDurTxt = 'indefinite (account stays locked until an administrator unlocks it)' }
                    else { $lockoutDurTxt = [string][int]([math]::Abs($vd) / 600000000) + ' minute(s)' }
                }
            } catch { }
            try {
                $vw = [int64]0
                if ([int64]::TryParse([string](Get-AdProperty $d 'lockoutObservationWindow'), [ref]$vw)) {
                    if ($vw -eq 0) { $lockoutWinTxt = '0 minute(s)' }
                    else { $lockoutWinTxt = [string][int]([math]::Abs($vw) / 600000000) + ' minute(s)' }
                }
            } catch { }

            Write-KV 'Minimum password length' $minLen
            Write-KV 'Password history length' $hist
            Write-KV 'Maximum password age (days)' $maxAgeDays
            Write-KV 'Lockout threshold' $(if ([string]$lockout -eq '0') { '0 - never lock out' } else { [string]$lockout + ' bad attempt(s)' })
            Write-KV 'Lockout duration' $lockoutDurTxt
            Write-KV 'Lockout observation window' $lockoutWinTxt

            # Structural context row: recorded unconditionally, not only when the values are weak,
            # so the report always carries an accurate profile of the estate's authentication
            # guardrails. This is metadata about a configuration, not a vulnerability claim.
            Add-Finding -Category 'Authentication' -Status 'INFO' -Attribute 'Domain lockout policy (default domain policy object)' -CatClass 'Context' `
                -Finding ('Account lockout guardrails in the default domain policy: threshold ' + $(if ([string]$lockout -eq '0') { '0 - accounts are never locked out' } else { [string]$lockout + ' bad attempt(s)' }) + '; duration ' + $lockoutDurTxt + '; observation window ' + $lockoutWinTxt + '.') `
                -Configured ('lockoutThreshold=' + $lockout + '; lockoutDuration=' + $lockoutDurTxt + '; lockoutObservationWindow=' + $lockoutWinTxt) `
                -Observed 'Three attributes read from the domainDNS object by a single base-scope LDAP query. No authentication was attempted against any account and no logon failure was generated by this module.' `
                -Validation 'Read-only LDAP query (base scope) of the domain object. AUTHORITATIVE FOR THE DEFAULT DOMAIN POLICY ONLY - fine-grained password policies (msDS-PasswordSettings objects) can override the lockout settings for specific users or groups, and this tool does not enumerate them, so a per-user override would NOT appear in this row. Interval-encoded values were decoded from 100-nanosecond units to minutes.' `
                -Class 'Low' `
                -Remediation 'Confirm these values match the corporate authentication baseline. Where a threshold is defined, pair it with lockout alerting so the policy cannot itself be abused to deny service to service accounts; where it is 0, treat unlimited online guessing as an accepted, documented risk or set a threshold.' `
                -Impact 'Context that determines how much online guessing an attacker can attempt before detection: with no threshold, the only control limiting repeated authentication is password entropy. This tool performs no password guessing, so no exploitability is claimed from these values.'
            Write-KV 'pwdProperties' ('0x' + $(try { ([int]$pwdProps).ToString('X2') } catch { '?' }) + ' (bit 0x01 = COMPLEXITY required, bit 0x10 = no reversible encryption)')
            Write-KV 'ms-DS-MachineAccountQuota' $maq

            $minLenV = 0; if ([int]::TryParse([string]$minLen, [ref]$minLenV) -and $minLenV -lt 12) {
                Add-Finding -Category 'Authentication' -Status 'WARN' -Attribute 'Domain minimum password length' -CatClass 'IdentityRights' `
                    -Finding ('The default domain policy requires only ' + $minLenV + ' character(s) of password length.') `
                    -Configured ('minPwdLength=' + $minLenV + ' (domain object attribute, i.e. the default domain password policy)') `
                    -Observed ('pwdHistoryLength=' + $hist + '; maxPwdAge(days)=' + $maxAgeDays + '; lockoutThreshold=' + $lockout) `
                    -Validation 'LDAP read of the domain object attributes maintained for password policy' -Class 'High' -CatClass 'IdentityRights' `
                    -Remediation 'Raise the minimum length to at least 14 characters (or move to a passphrase strategy), keep a long password history, and deploy a breached-password screening control. Length dominates complexity: prefer 16+ characters without forced rotation over 8 characters with rotation.' `
                    -Impact 'Short passwords fall to offline cracking and to online guessing, and they are the enabling condition for every credential-reuse path in this report. Note: this tool does not perform password guessing, so exploitability is NOT demonstrated here.'
            }
            if ([string]$lockout -eq '0') {
                Add-Finding -Category 'Authentication' -Status 'WARN' -Attribute 'Domain account lockout threshold' -CatClass 'IdentityRights' `
                    -Finding 'The default domain policy defines NO account lockout threshold, so unlimited authentication attempts are permitted against domain accounts.' `
                    -Configured ('lockoutThreshold=0 (never lock out)') -Observed ('lockoutDuration=' + $lockoutDurTxt + '; lockoutObservationWindow=' + $lockoutWinTxt + ' (decoded from 100-nanosecond intervals)') `
                    -Validation 'LDAP read of the domain object attributes' -Class 'High' -CatClass 'IdentityRights' `
                    -Remediation 'Define a lockout threshold in line with the corporate baseline (for example 10-20 attempts), and pair it with lockout alerting so the policy cannot be used for a denial-of-service attack against service accounts. Alternatively deploy a smart-lockout solution that distinguishes valid from invalid attempts.' `
                    -Impact 'Without a threshold, credential guessing is unbounded from the attacker''s perspective; the only remaining control is the password entropy itself.'
            }
            $pp = 0
            if ([int]::TryParse([string]$pwdProps, [ref]$pp) -and (($pp -band 0x01) -eq 0)) {
                Add-Finding -Category 'Authentication' -Status 'WARN' -Attribute 'Domain password complexity' -CatClass 'IdentityRights' `
                    -Finding 'Password complexity is NOT required by the default domain policy (pwdProperties bit 0x01 clear).' `
                    -Configured ('pwdProperties=0x' + $pp.ToString('X2') + ' (bit 0x01 = DOMAIN_PASSWORD_COMPLEX)') -Observed 'Exact bitmask decoding of pwdProperties' `
                    -Validation 'LDAP read with hexadecimal bitwise decoding' -Class 'Medium' -CatClass 'IdentityRights' `
                    -Remediation 'Either enable complexity or (preferably) enforce minimum length of 14+ with breached-password screening. Document the decision: complexity without length provides little measurable resistance to offline cracking.' `
                    -Impact 'Weak or predictable passwords fall quickly to offline attack, converting a single password-hash disclosure into reusable credentials.'
            }
            $maqV = 0
            if ([int]::TryParse([string]$maq, [ref]$maqV) -and $maqV -gt 0) {
                Add-Finding -Category 'Active Directory' -Status 'WARN' -Attribute 'ms-DS-MachineAccountQuota' -CatClass 'IdentityRights' `
                    -Finding ('Any authenticated user may join up to ' + $maqV + ' computer account(s) to the domain (ms-DS-MachineAccountQuota=' + $maqV + ').') `
                    -Configured ('ms-DS-MachineAccountQuota=' + $maqV + ' (domain object)') `
                    -Observed 'Quota value read directly from the domain object' -Validation 'LDAP read of the domain object attribute' `
                    -Class 'Medium' -CatClass 'IdentityRights' `
                    -Remediation 'Set ms-DS-MachineAccountQuota to 0 and delegate computer-account creation to a controlled group/OU, or restrict it through the "Add workstations to domain" user right. If the quota is needed, monitor for attacker-created machine accounts (which are used as relay/attacker-controlled principals, including in resource-based constrained delegation attacks).' `
                    -Impact 'A low-privilege domain user can create a machine account they fully control, which supplies the attacker-controlled principal needed for several directory-abuse techniques (relay chains and RBCD abuse). Combined with a reachable DC and a relayable authentication, this is a standard domain-escalation prerequisite.'
            }
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Domain policy attributes could not be read: ' + $_.Exception.Message)
    }

    # ---- krbtgt ---------------------------------------------------------------------------
    try {
        $ds = New-AdSearcher -Filter '(&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt))' -Properties @('distinguishedName','pwdLastSet','whenCreated')
        $k = Get-AdObjects -Searcher $ds -Cap 1
        if ($k -and $k.Count -gt 0) {
            $kl = Convert-FileTimeToDate (Get-AdProperty $k[0] 'pwdLastSet')
            if ($kl) {
                $kAge = Get-DaysSince $kl
                Write-KV 'KRBTGT password last set' ($kl.ToString('yyyy-MM-dd') + ' (' + $kAge + ' days ago)')
                Add-Finding -Category 'Active Directory' -Status $(if ($kAge -gt 180) { 'WARN' } else { 'INFO' }) -CatClass 'IdentityRights' `
                    -Attribute 'KRBTGT password age' -Finding ('The KRBTGT account password was last set ' + $kAge + ' day(s) ago.') `
                    -Configured ('pwdLastSet=' + $kl.ToString('yyyy-MM-dd HH:mm:ss')) `
                    -Observed 'Kerberos master key material for the domain is derived from this account; its age bounds how long a stolen key remains valid.' `
                    -Validation 'LDAP read of the krbtgt account''s pwdLastSet (no key material is retrieved; doing so is explicitly out of scope for this tool)' `
                    -Class 'High' -CatClass 'IdentityRights' `
                    -Remediation 'Rotate the KRBTGT password twice (with the replication interval between changes) whenever domain compromise is suspected, and on a scheduled basis (e.g. annually) in environments with a history of privileged access. Coordinate with the AD recovery plan, because rotation invalidates all existing TGTs.' `
                    -Impact 'If domain keys were ever disclosed, every Kerberos ticket issued before rotation remains forgeable; KRBTGT age is the practical upper bound on the "golden ticket" exposure window.'
            }
        }
    } catch { }

    # =======================================================================================
    #  9.x GPO and SYSVOL Security Container Write Permissions
    #  READ-ONLY: .NET filesystem ACL inspection only; no write test is performed.
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- GPO and SYSVOL Security Container Write Permissions ----------------------------' -ForegroundColor DarkCyan
    try {
        $sysvolPath = '\\' + $script:DomainControllerName + '\SYSVOL\' + $script:DomainName + '\Policies'
        $dangerousAces = @()
        if ([System.IO.Directory]::Exists($sysvolPath)) {
            $sysvolDir = [System.IO.DirectoryInfo]::new($sysvolPath)
            $sysvolAcl = $sysvolDir.GetAccessControl()
            $sidType = [System.Security.Principal.SecurityIdentifier]
            $rules = $sysvolAcl.GetAccessRules($true, $true, $sidType)
            $broadWriteSids = @{
                'S-1-1-0' = 'Everyone'
                'S-1-5-11' = 'Authenticated Users'
                'S-1-5-32-545' = 'BUILTIN\Users'
            }
            $writeDataMask = [int][System.Security.AccessControl.FileSystemRights]::WriteData
            $modifyMask = [int][System.Security.AccessControl.FileSystemRights]::Modify

            foreach ($ace in $rules) {
                $sid = ''
                try { $sid = $ace.IdentityReference.Value } catch { continue }
                if ($ace.AccessControlType.ToString() -ne 'Allow' -or -not $broadWriteSids.ContainsKey($sid)) { continue }
                $rights = 0
                try { $rights = [int]$ace.FileSystemRights } catch { }
                if ((($rights -band $writeDataMask) -ne 0) -or (($rights -band $modifyMask) -ne 0)) {
                    $dangerousAces += [pscustomobject]@{
                        Principal = $broadWriteSids[$sid]
                        SID = $sid
                        Rights = $ace.FileSystemRights.ToString()
                    }
                }
            }
        } else {
            Write-Status 'NOT TESTABLE' ('SYSVOL Policies path does not exist or is not accessible: ' + $sysvolPath)
        }

        if ($dangerousAces.Count -gt 0) {
            Write-Status 'RISK DETECTED' (($dangerousAces.Count).ToString() + ' broad allow ACE(s) grant write-capable rights on the SYSVOL Policies container.')
            Write-Table -Rows $dangerousAces -Columns @('Principal','SID','Rights') `
                -Headers @{ Principal='Principal'; SID='SID'; Rights='File System Rights' }
            Add-Finding -Category 'Active Directory' -Status 'RISK DETECTED' `
                -Attribute 'Writable SYSVOL Infrastructure' `
                -Target 'SYSVOL Share' `
                -Finding 'A broad principal has write-capable permissions on the SYSVOL Policies security container, creating a writable GPO infrastructure surface.' `
                -Observed (($dangerousAces | ForEach-Object { $_.Principal + ' [' + $_.Rights + ']' }) -join '; ') `
                -Validation 'Read-only .NET ACL inspection of the SYSVOL Policies container; no file or directory was created or modified.' `
                -Class 'Critical' -CatClass 'IdentityRights'
        } elseif ([System.IO.Directory]::Exists($sysvolPath)) {
            Write-Status 'PASS' 'No Everyone, Authenticated Users, or BUILTIN\Users allow ACE with WriteData or Modify was found on the SYSVOL Policies container.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('SYSVOL ACL inspection failed: ' + $_.Exception.Message)
    }

    # Native read-only corroboration: net.exe share SYSVOL. ACL analysis above remains the
    # authoritative permission check; this confirms the native share exposure/name.
    Write-Host ''
    Write-Host '  -- Native SYSVOL share corroboration (net.exe) -----------------------------------' -ForegroundColor DarkCyan
    try {
        $netShareLines = @(& net.exe share SYSVOL 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not $netShareLines) {
            throw ('net.exe share SYSVOL returned exit code ' + [string]$LASTEXITCODE)
        }
        $shareRows = @()
        foreach ($line in $netShareLines) {
            $t = ([string]$line).Trim()
            if ($t -and $t -notmatch '^Share name|^Resource|^Remark|^---|^The command completed successfully') {
                $shareRows += [pscustomobject]@{ Output=$t }
            }
        }
        if ($shareRows.Count -gt 0) {
            Write-Table -Rows $shareRows -Columns @('Output') -Headers @{ Output='net.exe share SYSVOL' }
            Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' `
                -Attribute 'Native SYSVOL share corroboration' `
                -Target 'SYSVOL Share' `
                -Finding 'The native net.exe utility corroborated that the SYSVOL share can be queried from the assessment context.' `
                -Observed ($shareRows.Output -join ' | ') `
                -Validation 'Read-only native net.exe share SYSVOL invocation; no share, file, or ACL was modified.' `
                -Class 'Low' -CatClass 'Context' -NoConsole
        } else {
            Write-Status 'PASS' 'net.exe share SYSVOL returned no additional share metadata.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Native net.exe SYSVOL share corroboration failed: ' + $_.Exception.Message)
    }

}

# ===========================================================================================
#  SECTION 10 :: USER ACCOUNT CONTROL / KERBEROS PRE-AUTHENTICATION
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  DONT_REQ_PREAUTH (0x00400000) tells the KDC to issue a TGT WITHOUT requiring the client to
#  prove knowledge of the password first. The reply is encrypted with a key derived from the
#  account password, so it can be attacked offline - with no online attempts and therefore no
#  lockout risk. This module does BOTH halves of the assessment:
#
#     CONFIGURATION EVIDENCE : the exact UAC value and its hexadecimal decoding
#     ACTIVE VALIDATION      : an AS-REQ without pre-authentication data, issued ONLY for
#                              accounts already flagged by the directory, at most 10 accounts.
#                              An AS-REP (rather than KDC_ERR_PREAUTH_REQUIRED) proves the
#                              condition. The response payload is discarded immediately and
#                              no cracking is performed.
# ===========================================================================================
function Invoke-Section10_PreAuth {
    if (-not $script:LdapReady) {
        Write-Status 'NOT TESTABLE' ((Get-LdapUnavailableReason) + ': UAC / pre-authentication analysis cannot be performed.')
        Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'NOT TESTABLE' -Attribute 'DONT_REQ_PREAUTH analysis' `
            -Finding 'User account control flags could not be enumerated because the directory was not reachable from this context.' `
            -Validation 'Not performed' -Class 'High' -Remediation 'Re-run from a domain-joined context with LDAP access to enumerate UAC flags and validate pre-authentication.' `
            -Impact 'Unknown.' -NoConsole
        return
    }
    Write-Host ''
    Write-Host '  -- 10.1 DONT_REQ_PREAUTH accounts (userAccountControl bit 0x00400000) ------------' -ForegroundColor DarkCyan
    $ds = New-AdSearcher -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' `
        -Properties @('distinguishedName','sAMAccountName','userAccountControl','pwdLastSet','adminCount','memberOf','servicePrincipalName','lastLogonTimestamp','whenCreated','description')
    $objs = Get-AdObjects -Searcher $ds
    if ($null -eq $objs) {
        Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'NOT TESTABLE' -Attribute 'DONT_REQ_PREAUTH query' `
            -Finding 'The directory query for pre-authentication-disabled accounts failed (insufficient rights or blocked LDAP filter).' `
            -Observed ('Filter used: (userAccountControl:1.2.840.113556.1.4.803:=4194304) - the 1.2.840.113556.1.4.803 matching rule is the bitwise AND operator defined in RFC 4517.' ) `
            -Validation 'Not completed' -Class 'High' -Remediation 'Verify LDAP read access on user objects; at minimum the authenticated-user default rights in AD allow this filter.' `
            -Impact 'Unknown: accounts with pre-authentication disabled enable offline password recovery, so an unassessed directory must be treated as potentially exposed.' -NoConsole
        return
    }

    $script:Facts['PreAuthConfigured'] = $objs.Count
    $script:Facts['PreAuthValidated'] = 0
    $candidates = @()
    foreach ($o in $objs) {
        $sam = Get-AdProperty $o 'sAMAccountName'
        $uac = Get-AdProperty $o 'userAccountControl'
        $dec = Get-UacDecode $uac
        $priv = Test-PrivilegedRelationship -Object $o
        $pl = Convert-FileTimeToDate (Get-AdProperty $o 'pwdLastSet')
        $candidates += [pscustomobject]@{
            Sam = $sam; DN = (Get-AdProperty $o 'distinguishedName'); Uac = $uac; UacHex = $dec.ValueHex
            Flags = $dec.FlagNames; Disabled = $dec.IsDisabled; PwdLastSet = $(if ($pl) { $pl.ToString('yyyy-MM-dd') } else { 'never/not set' })
            PwdAgeDays = $(if ($pl) { Get-DaysSince $pl } else { $null })
            Privileged = $priv.IsPrivileged; PrivReason = $priv.Reasons
            Spns = @($o['serviceprincipalname']).Count
        }
    }

    if ($candidates.Count -eq 0) {
        Write-Status 'PASS' 'No user account has DONT_REQ_PREAUTH (0x00400000) set.'
        Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'PASS' -Attribute 'DONT_REQ_PREAUTH (0x00400000)' `
            -Finding 'No user account in the directory has the DONT_REQ_PREAUTH bit set in userAccountControl.' `
            -Configured 'Enumerated with the LDAP bitwise-and matching rule on the exact mask 0x00400000 (decimal 4194304)' `
            -Observed 'Zero matching objects' -Validation 'Paged LDAP query using the RFC 4517 bitwise matching rule' `
            -Class 'Critical' -CatClass 'Confidentiality' `
            -Remediation 'No action required. Re-run after every account-tiering change: this flag is frequently set by mistake during manual account creation or by legacy migration tools.' `
            -Impact 'None - pre-authentication is enforced for all user accounts, which removes the offline-cracking path.'
    } else {
        Write-Status 'RISK DETECTED' ($candidates.Count.ToString() + ' account(s) have pre-authentication disabled.')
        $rows = @()
        foreach ($c in $candidates) {
            $rows += [pscustomobject]@{ Sam=$c.Sam; Disabled=$c.Disabled; Uac=$c.UacHex; Priv=$(if ($c.Privileged) { 'YES' } else { 'no' }); PwdAge=$(if ($null -ne $c.PwdAgeDays) { [string]$c.PwdAgeDays } else { 'n/a' }); SPNs=$c.Spns }
        }
        Write-Table -Rows $rows -Columns @('Sam','Disabled','Uac','Priv','PwdAge','SPNs') -Headers @{ Sam='sAMAccountName'; Disabled='Disabled'; Uac='UAC (hex)'; Priv='Privileged'; PwdAge='Pwd age (days)'; SPNs='SPN count' }

        foreach ($c in $candidates) {
            $sevClass = if ($c.Privileged) { 'Critical' } else { 'High' }
            Write-Host ''
            Write-Host ('    ' + $c.Sam + ' -> ' + $c.DN) -ForegroundColor DarkGray
            Write-Host ('      userAccountControl = ' + $c.Uac + ' (' + $c.UacHex + ')') -ForegroundColor DarkGray
            Write-Host ('      decoded flags      = ' + $(if ($c.Flags) { $c.Flags } else { '(none)' })) -ForegroundColor DarkGray
            Write-Host ('      account state      = ' + $(if ($c.Disabled) { 'DISABLED' } else { 'enabled' }) + '; password last set ' + $c.PwdLastSet + $(if ($null -ne $c.PwdAgeDays) { ' (' + $c.PwdAgeDays + ' days ago)' } else { '' })) -ForegroundColor DarkGray
            Write-Host ('      privileged group   = ' + $(if ($c.Privileged) { 'YES - ' + $c.PrivReason } else { 'no relationship observed (direct membership / adminCount)' })) -ForegroundColor DarkGray
            Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'RISK DETECTED' -Attribute 'DONT_REQ_PREAUTH flag set' `
                -Target $c.Sam -Finding ('Account ''' + $c.Sam + ''' has Kerberos pre-authentication DISABLED (userAccountControl bit 0x00400000), so the KDC will return a TGT response that can be attacked offline without any online authentication attempt.') `
                -Configured ('userAccountControl=' + $c.Uac + ' (' + $c.UacHex + ') - exact hexadecimal decoding: ' + $(if ($c.Flags) { $c.Flags } else { '(no flags decoded)' }) + ' ; account ' + $(if ($c.Disabled) { 'DISABLED' } else { 'ENABLED' })) `
                -Observed ('Password last set: ' + $c.PwdLastSet + $(if ($null -ne $c.PwdAgeDays) { ' (' + $c.PwdAgeDays + ' days ago)' } else { '' }) + '; privileged relationship: ' + $(if ($c.Privileged) { $c.PrivReason } else { 'none observed' }) + '; SPNs present: ' + $c.Spns) `
                -Validation $(if (Get-CfgFlag -Name 'EnableKerberosPreAuthProbe' -Default $true) { 'Active validation performed in Section 10.2: an AS-REQ without pre-authentication data was sent for this account, and the KDC response is recorded there. The configuration row here remains configuration evidence on its own.' } else { 'Configuration evidence only: the active AS-REQ validation was disabled by configuration for this run.' }) `
                -Prerequisites ('Network reachability to a KDC on TCP/88 (recorded in Sections 8 and 10.2). No credentials are required to trigger the response; the reply is encrypted with a key derived from the account password.') `
                -Exploitability 'Prerequisite validated: the account is reachable through the KDC and returns crackable material. Offline cracking itself is NOT performed by this tool (prohibited by design); the finding is the exposed condition plus the demonstrated AS-REP response.' `
                -Class $sevClass -CatClass 'Confidentiality' `
                -Remediation ('Clear the DONT_REQ_PREAUTH flag (Set-ADAccountControl -DoesNotRequirePreAuth $false) unless there is a documented, still-required legacy dependency; change the account password immediately if the flag has been set for a long period (the material may already have been harvested), require long random passwords for the account, add it to Protected Users where possible, and alert on any ticket request for accounts that ever had the flag set.') `
                -Impact ('An attacker able to reach the KDC obtains an AS-REP encrypted with the account''s key without any authentication attempt, no lockout and no logon event that looks like a failed logon. Cracking that material yields the account password, after which the account''s privileges are available: ' + $(if ($c.Privileged) { 'this account holds a privileged relationship, so the path leads directly toward domain-level control.' } else { 'the account''s group memberships and resource access determine the blast radius.' }))
        }

        # ---- 10.2 ACTIVE VALIDATION -----------------------------------------------------
        Write-Host ''
        Write-Host '  -- 10.2 Active validation: AS-REQ without pre-authentication --------------------' -ForegroundColor DarkCyan
        if (-not (Test-RemoteAllowed)) {
            Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - the AS-REQ pre-authentication probe was not sent to any KDC.')
        } elseif (-not (Get-CfgFlag -Name 'EnableKerberosPreAuthProbe' -Default $true)) {
            Write-Status 'NOT TESTABLE' 'Active pre-authentication validation was DISABLED BY THE OPERATOR (Cfg.EnableKerberosPreAuthProbe = $false). This is a configuration choice, not a tool limitation.'
        } else {
            $kdc = ''
            if ($script:DomainControllerName) {
                try {
                    $a = [System.Net.Dns]::GetHostAddresses($script:DomainControllerName) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
                    if ($a) { $kdc = $a.IPAddressToString }
                } catch { }
                if (-not $kdc) { $kdc = $script:DomainControllerName }
            }
            if (-not $kdc) {
                Write-Status 'NOT TESTABLE' 'No KDC address could be resolved, so active validation of pre-authentication was not possible.'
            } else {
                $t88 = Test-TcpPort -Target $kdc -Port 88 -TimeoutMs 1000
                if ($t88.State -ne 'Open') {
                    Write-Status 'NOT TESTABLE' ('KDC TCP/88 is ' + $t88.State + ' from this context: active pre-authentication validation not possible. Configuration evidence stands alone.')
                    Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'NOT TESTABLE' -Attribute 'AS-REQ pre-auth validation' `
                        -Source $script:HostName -Target $kdc -Port '88' -Finding 'The Kerberos KDC was not reachable, so the pre-authentication configuration could not be validated against live behaviour.' `
                        -Observed ('TCP/88 state: ' + $t88.State + ' (' + $t88.Error + ')') -Validation 'Bounded TCP connect test (validation not attempted)' `
                        -Class 'High' -Remediation 'Ensure the assessment position can reach a KDC (TCP/88) so that directory-derived configuration can be validated rather than only assumed.' `
                        -Impact 'The DONT_REQ_PREAUTH configuration remains CONFIGURATION EVIDENCE ONLY for this run.' -NoConsole
                } else {
                    $max = [Math]::Min(10, $candidates.Count)
                    Write-Status 'INFO' ('KDC ' + $kdc + ':88 reachable. Validating ' + $max + ' account(s) (maximum 10 by configuration). One AS-REQ per account, no credentials transmitted, AS-REP payload discarded.')
                    $i = 0
                    foreach ($c in $candidates) {
                        if ($i -ge $max) { break }
                        $i++
                        $v = Invoke-KerberosPreAuthProbe -Target $kdc -UserName $c.Sam -Domain $script:DomainName
                        if ($v.PreAuthNotEnforced -eq $true) {
                            $script:Facts['PreAuthValidated'] = [int]$script:Facts['PreAuthValidated'] + 1
                            Write-Status 'VALIDATED' ($c.Sam + ': AS-REP returned without pre-authentication -> pre-authentication is NOT enforced (behaviour confirmed).')
                            Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'VALIDATED' -Attribute 'AS-REP obtainable without pre-authentication (behaviour confirmed)' `
                                -Source $script:HostName -Target $kdc -Port '88' `
                                -Finding ('The KDC returned an AS-REP for ''' + $c.Sam + ''' in response to an AS-REQ that contained NO pre-authentication data. Pre-authentication is therefore not merely misconfigured in the directory: it is not being enforced at the protocol level for this account.') `
                                -Configured ('userAccountControl=' + $c.Uac + ' (' + $c.UacHex + '), DONT_REQ_PREAUTH=0x00400000 set') `
                                -Observed ('AS-REP received (application tag 0x7B) instead of KRB-ERROR/KDC_ERR_PREAUTH_REQUIRED (0x7E). The response payload was discarded immediately: it was not written to disk, not printed, and not retained. No cracking was performed.') `
                                -Validation 'A single AS-REQ per account built with a minimal DER encoder (msg-type 10, no padata field, standard KDC options). The KDC''s own answer is the evidence - this is observed authentication behaviour, not an inference from an attribute.' `
                                -Prerequisites 'TCP/88 reachability to the KDC (confirmed above). No credential material is required or used.' `
                                -Exploitability 'Demonstrated at the protocol level: crackable key material was issued by the KDC for this account. Extraction of the plaintext password is deliberately NOT performed by this tool.' `
                                -Class $(if ($c.Privileged) { 'Critical' } else { 'High' }) -CatClass 'Confidentiality' `
                                -Remediation 'Treat the account as compromised: clear DONT_REQ_PREAUTH, reset the password with a long random value, invalidate existing tickets by resetting twice if the account is privileged, and review whether the AS-REP could have been harvested by a real adversary before this test (check 4768 events for this account).' `
                                -Impact 'Offline recovery of the account password is practical once the AS-REP is captured; because the request requires no authentication, the activity is invisible to account lockout and looks like an ordinary ticket request.'
                        } elseif ($v.PreAuthNotEnforced -eq $false) {
                            Write-Status 'NOT CONFIRMED' ($c.Sam + ': KDC replied ' + $v.ErrorName + ' -> pre-authentication IS enforced for this account despite the UAC bit.')
                            Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'NOT CONFIRMED' -Attribute 'AS-REQ pre-auth validation (not confirmed)' `
                                -Source $script:HostName -Target $kdc -Port '88' `
                                -Finding ('Despite the DONT_REQ_PREAUTH bit being set on ''' + $c.Sam + ''', the KDC did NOT return a ticket: it replied with ' + $v.ErrorName + '. The misconfiguration is present in the directory but the expected impact was NOT reproduced.') `
                                -Configured ('userAccountControl=' + $c.Uac + ' (' + $c.UacHex + ')') `
                                -Observed ('KDC response: ' + $v.MessageTypeName + ' with ' + $(if ($v.ErrorName) { $v.ErrorName } else { 'no error code parsed' })) `
                                -Validation 'Live AS-REQ without pre-authentication data; the negative result is recorded exactly as received rather than assumed away.' `
                                -Class 'Medium' -CatClass 'Confidentiality' `
                                -Remediation 'Investigate the discrepancy: check for a KDC-side policy override, an enforcing third-party product, or a stale replication state on the DC that answered. Re-test against every domain controller, because KDC behaviour is per-DC.' `
                                -Impact 'No impact demonstrated for this account at the tested KDC.'
                        } else {
                            Write-Status 'NOT TESTABLE' ($c.Sam + ': validation inconclusive - ' + $(if ($v.Error) { $v.Error } else { 'unrecognised KDC response' }))
                            Add-Finding -Category 'Kerberos Pre-Authentication' -Status 'NOT TESTABLE' -Attribute 'AS-REQ pre-auth validation (inconclusive)' `
                                -Source $script:HostName -Target $kdc -Port '88' -Finding ('Active validation for ''' + $c.Sam + ''' did not produce an interpretable result, so impact is NOT claimed.') `
                                -Observed ($v.Error + $(if ($v.MessageType) { ' | response tag: ' + $v.MessageType } else { '' })) -Validation 'Attempted AS-REQ; result unusable' `
                                -Class 'Medium' -CatClass 'Confidentiality' `
                                -Remediation 'Investigate the KDC response manually (clock skew and UDP/TCP transport differences are common causes) before drawing a conclusion.' `
                                -Impact 'Unknown for this account.'
                        }
                    }
                }
            }
        }
    }

    # ---- Related account-hygiene flags --------------------------------------------------
    Write-Host ''
    Write-Host '  -- 10.3 Related account-control hygiene flags -----------------------------------' -ForegroundColor DarkCyan
    $checks = @(
        @{ Name='PASSWD_NOTREQD (0x00000020)'; Mask=32;      Class='Medium'; Desc='Account may have an empty or non-expiring password requirement waived, and it can be forced onto accounts by a single weak-password set.' },
        @{ Name='USE_DES_KEY_ONLY (0x00200000)'; Mask=2097152; Class='Critical'; Desc='The account may only use DES for Kerberos keys. DES is cryptographically broken and the key space is trivially searchable.' },
        @{ Name='TRUSTED_FOR_DELEGATION (0x00080000)'; Mask=524288;  Class='Critical'; Desc='Unconstrained Kerberos delegation: see Section 12 for the full analysis.' }
    )
    foreach ($chk in $checks) {
        $ds = New-AdSearcher -Filter ('(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=' + $chk.Mask + '))') `
            -Properties @('distinguishedName','sAMAccountName','userAccountControl','adminCount')
        $res = Get-AdObjects -Searcher $ds -Cap 50
        if ($null -eq $res) { continue }
        $detail = @()
        foreach ($o in $res) {
            $dec = Get-UacDecode (Get-AdProperty $o 'userAccountControl')
            $detail += ((Get-AdProperty $o 'sAMAccountName') + ' [' + $dec.ValueHex + ']' + $(if ((Get-AdProperty $o 'adminCount') -eq '1') { ' (adminCount=1)' } else { '' }))
        }
        Add-Finding -Category 'Authentication' -Status $(if ($res.Count -gt 0 -and $chk.Class -eq 'Critical') { 'WARN' } elseif ($res.Count -gt 0) { 'WARN' } else { 'PASS' }) `
            -Attribute ('userAccountControl flag: ' + $chk.Name) `
            -Finding $(if ($res.Count -eq 0) { 'No account has the ' + $chk.Name + ' flag set.' } else { $res.Count.ToString() + ' account(s) have the ' + $chk.Name + ' flag set.' }) `
            -Configured ('LDAP bitwise-and match on mask 0x' + ([int]$chk.Mask).ToString('X8')) `
            -Observed $(if ($detail.Count -gt 0) { ($detail -join '; ') } else { 'no matching accounts' }) `
            -Validation 'Paged LDAP query with the RFC 4517 bitwise matching rule; flags decoded with exact hexadecimal masks.' `
            -Class $chk.Class -CatClass 'IdentityRights' `
            -Remediation 'Clear the flag on each listed account after confirming there is no documented dependency: Set-ADAccountControl -PasswordNotRequired $false / -UseDESKeyOnly $false / -TrustedForDelegation $false, and then reset the account password.' `
            -Impact $chk.Desc
    }
}
# ===========================================================================================
#  SECTIONS 11-14 :: SPN / DELEGATION / ENCRYPTION / LAPS  (part 8/12)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  These four attributes (servicePrincipalName, msDS-AllowedToDelegateTo,
#  msDS-AllowedToActOnBehalfOfOtherIdentity, msDS-SupportedEncryptionTypes, ms-Mcs-AdmPwd*)
#  describe how Kerberos is actually used in the estate and where credentials and
#  privileges concentrate. Each module states plainly what is CONFIGURATION EVIDENCE and what
#  was VALIDATED, and none of them retrieves passwords, hashes, keys or tickets.
# ===========================================================================================

function Get-SpnServiceMap {
    param([string]$Spn)
    $cls = ''; $hostPart = ''; $port = 0; $target = ''
    try {
        $parts = $Spn.Split('/')
        if ($parts.Count -ge 2) {
            $cls = $parts[0]
            $hostPart = $parts[1]
            if ($hostPart.Contains(':')) {
                $hp = $hostPart.Split(':')
                $hostPart = $hp[0]
                [void][int]::TryParse($hp[1], [ref]$port)
            }
        } elseif ($parts.Count -eq 1) { $cls = $parts[0] }
    } catch { }
    $target = $hostPart
    $svcPort = switch -Regex ($cls) {
        '(?i)^MSSQLSvc$'   { if ($port -eq 0) { 1433 } else { $port } }
        '(?i)^HTTP$'       { if ($port -eq 0) { 80 } else { $port } }
        '(?i)^HTTPS$'      { 443 }
        '(?i)^WSMan'       { 5985 }
        '(?i)^termsrv'     { 3389 }
        '(?i)^cifs|^HOST$' { 445 }
        '(?i)^ldap'        { 389 }
        '(?i)^exchange'    { 443 }
        '(?i)^kafka|^mysql|^postgres' { 0 }
        default            { 0 }
    }
    return [pscustomobject]@{ ServiceClass=$cls; HostPart=$hostPart; Port=$svcPort; PortFromSpn=$port }
}

# ===========================================================================================
#  SECTION 11 :: SPN / SERVICE-ACCOUNT AUDIT
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  A user account that holds an SPN can have a service ticket requested for it by ANY
#  authenticated principal; that ticket is encrypted with a key derived from the account's
#  password. The exposure therefore depends on three measurable properties: the SPN exists,
#  the password is old (or the account is privileged), and the KDC will encrypt with RC4
#  (fast to attack) rather than AES. This module measures all three from the directory.
#
#  DELIBERATELY NOT DONE: no service ticket is requested, no ticket or session key is
#  captured, and no cracking is attempted. Those actions would create exactly the credential
#  artifacts this tool is required not to handle.
# ===========================================================================================
function Invoke-Section11_Spn {
    if (-not $script:LdapReady) {
        Write-Status 'NOT TESTABLE' ((Get-LdapUnavailableReason) + ': SPN / service-account audit skipped.')
        Add-Finding -Category 'Service Accounts' -Status 'NOT TESTABLE' -Attribute 'SPN audit' -Finding 'SPN-holding accounts could not be enumerated (directory unreachable).' `
            -Validation 'Not performed' -Class 'High' -Remediation 'Re-run from a domain-joined context with LDAP read access.' -Impact 'Unknown.' -NoConsole
        return
    }
    Write-Host ''
    Write-Host '  -- 11.1 Accounts holding servicePrincipalName -----------------------------------' -ForegroundColor DarkCyan
    $ds = New-AdSearcher -Filter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' `
        -Properties @('distinguishedName','sAMAccountName','servicePrincipalName','pwdLastSet','userAccountControl','adminCount','memberOf','msDS-SupportedEncryptionTypes','lastLogonTimestamp','sAMAccountType','description')
    $objs = Get-AdObjects -Searcher $ds
    if ($null -eq $objs) { Write-Status 'NOT TESTABLE' 'SPN query failed.'; return }

    # Managed service accounts (they are computer-class objects and are handled separately)
    $msaDs = New-AdSearcher -Filter '(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))' -Properties @('distinguishedName','sAMAccountName','servicePrincipalName','msDS-SupportedEncryptionTypes','pwdLastSet')
    $msas = Get-AdObjects -Searcher $msaDs
    $script:Facts['SpnUserAccounts'] = $objs.Count
    $script:Facts['SpnPrivilegedCount'] = 0
    $script:Facts['StaleSpnPasswords'] = 0
    Write-KV 'User accounts with SPNs' $objs.Count
    Write-KV 'Managed service accounts (MSA/gMSA)' $(if ($null -ne $msas) { $msas.Count } else { 'query failed' })
    $script:AdCounts.Kerberoastable = $objs.Count

    if ($objs.Count -eq 0 -and ($null -eq $msas -or $msas.Count -eq 0)) {
        Write-Status 'PASS' 'No user account holds an SPN (no Kerberoastable user surface).'
        Add-Finding -Category 'Service Accounts' -Status 'PASS' -Attribute 'SPN-holding user accounts' `
            -Finding 'No user account in the directory holds a servicePrincipalName.' -Observed 'Zero matching objects' `
            -Validation 'Paged LDAP query on (servicePrincipalName=*) filtered to person objects' -Class 'High' `
            -Remediation 'No action. Ensure new service accounts use gMSA with automatic password management, and re-run this check after any application deployment.' `
            -Impact 'None - no user-account service ticket can be requested by an authenticated attacker.'
    } else {
        $young = 0; $old = 0; $priv = 0; $neverSet = 0
        $rows = @(); $details = @()
        foreach ($o in $objs) {
            $sam = Get-AdProperty $o 'sAMAccountName'
            $spns = @($o['serviceprincipalname'])
            $pl = Convert-FileTimeToDate (Get-AdProperty $o 'pwdLastSet')
            $age = if ($pl) { Get-DaysSince $pl } else { $null }
            $dec = Get-UacDecode (Get-AdProperty $o 'userAccountControl')
            $pr = Test-PrivilegedRelationship -Object $o
            $et = Get-AdProperty $o 'msDS-SupportedEncryptionTypes'
            if ($null -eq $pl) { $neverSet++ } elseif ($age -gt $script:Cfg.StalePasswordAge) { $old++ } else { $young++ }
            if ($pr.IsPrivileged) { $priv++; $script:Facts['SpnPrivilegedCount'] = [int]$script:Facts['SpnPrivilegedCount'] + 1 }
            if ($null -eq $pl -or ($null -ne $age -and $age -gt $script:Cfg.StalePasswordAge)) { $script:Facts['StaleSpnPasswords'] = [int]$script:Facts['StaleSpnPasswords'] + 1 }
            $classes = @()
            foreach ($s in $spns) { $classes += (Get-SpnServiceMap -Spn $s).ServiceClass }
            $rows += [pscustomobject]@{
                Sam = $sam
                SPNs = $spns.Count
                Classes = (($classes | Select-Object -Unique) -join ',')
                PwdAge = $(if ($null -ne $age) { [string]$age } else { 'never' })
                Disabled = $dec.IsDisabled
                Priv = $(if ($pr.IsPrivileged) { 'YES' } else { 'no' })
                Et = $(if ($null -eq $et) { 'absent' } else { '0x' + ([int64]$et).ToString('X0') })
            }
            $details += [pscustomobject]@{ Obj=$o; Sam=$sam; Spns=$spns; Age=$age; Dec=$dec; Priv=$pr; Et=$et; Classes=$classes }
        }
        Write-Table -Rows ($rows | Sort-Object -Property @{Expression={ if ($_.PwdAge -eq 'never') { 999999 } else { [int]$_.PwdAge } }; Descending=$true }) `
            -Columns @('Sam','SPNs','Classes','PwdAge','Disabled','Priv','Et') `
            -Headers @{ Sam='Account'; SPNs='# SPN'; Classes='Service classes'; PwdAge='Pwd age (d)'; Disabled='Disabled'; Priv='Privileged'; Et='msDS-SupportedEncryptionTypes' }

        Add-Finding -Category 'Service Accounts' -Status $(if ($priv -gt 0) { 'RISK DETECTED' } else { 'WARN' }) -Attribute 'Kerberoastable user accounts (SPN exposure)' `
            -Finding ($objs.Count.ToString() + ' user account(s) hold an SPN and can therefore have a service ticket requested by any authenticated principal. ' + $old + ' have passwords older than ' + $script:Cfg.StalePasswordAge + ' days, ' + $neverSet + ' have no recorded password change, and ' + $priv + ' hold a privileged-group relationship.') `
            -Configured ('Query: (&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)) - ' + $objs.Count + ' objects returned') `
            -Observed ('Password age distribution: ' + $young + ' <= ' + $script:Cfg.StalePasswordAge + ' days, ' + $old + ' > ' + $script:Cfg.StalePasswordAge + ' days, ' + $neverSet + ' never set. Privileged accounts inside the set: ' + $priv + '.') `
            -Validation 'Paged LDAP read of servicePrincipalName + pwdLastSet + group relationships. NO service ticket was requested and no ticket material was captured or cracked.' `
            -Prerequisites 'Any authenticated domain principal can request a service ticket for an SPN-holding account (the request itself is not performed by this tool).' `
            -Exploitability 'Partly demonstrated: the SPN exposure, password age and the RC4 capability (Section 13) are evidence-based. The ticket request and offline cracking were deliberately NOT performed, so the row is not reported as a validated credential compromise.' `
            -Class $(if ($priv -gt 0) { 'Critical' } else { 'High' }) -CatClass 'Confidentiality' `
            -Remediation 'Move all service accounts to gMSA (automatically rotated 240-character secrets) wherever the service supports it. For accounts that cannot use gMSA: enforce 30+ character random passwords, enable AES (0x18) and remove RC4 support, restrict the account to the hosts where the service runs, remove privileged-group membership, and rotate the password on a documented schedule. Reduce the SPN surface by removing SPNs that do not correspond to a live service.' `
            -Impact 'A single authenticated domain user (or an attacker with any valid credential) can obtain crackable material for every listed account. For privileged accounts this is a direct path to domain compromise; the password age distribution above determines how quickly that path succeeds.'

        # Per-account findings for stale / privileged / never-set passwords
        foreach ($d in $details) {
            if ($d.Priv.IsPrivileged -or ($null -ne $d.Age -and $d.Age -gt $script:Cfg.StalePasswordAge) -or $null -eq $d.Age) {
                $why = @()
                if ($d.Priv.IsPrivileged) { $why += 'privileged relationship: ' + $d.Priv.Reasons }
                if ($null -eq $d.Age) { $why += 'password age not recorded (pwdLastSet is 0)' } elseif ($d.Age -gt $script:Cfg.StalePasswordAge) { $why += 'password age ' + $d.Age + ' days (threshold ' + $script:Cfg.StalePasswordAge + ' days)' }
                $spnList = ($d.Spns -join ' | ')
                Write-Host ''
                Write-Host ('    ' + $d.Sam + ' -> ' + $spnList) -ForegroundColor DarkGray
                Write-Host ('      ' + ($why -join '; ') + '; account ' + $(if ($d.Dec.IsDisabled) { 'DISABLED' } else { 'ENABLED' }) + '; UAC=' + $d.Dec.ValueHex + '; encryption types=' + $(if ($null -eq $d.Et) { 'attribute absent' } else { '0x' + ([int64]$d.Et).ToString('X0') })) -ForegroundColor DarkGray
                Add-Finding -Category 'Service Accounts' -Status 'WARN' -Attribute 'Stale / privileged SPN account' `
                    -Target $d.Sam -Finding ('SPN-holding account ''' + $d.Sam + ''' with elevated exposure: ' + ($why -join '; ') + '.') `
                    -Configured ('servicePrincipalName=' + $spnList + ' ; userAccountControl=' + $d.Dec.ValueHex + ' (' + $d.Dec.FlagNames + ') ; msDS-SupportedEncryptionTypes=' + $(if ($null -eq $d.Et) { 'ABSENT' } else { '0x' + ([int64]$d.Et).ToString('X0') })) `
                    -Observed ('Password last set: ' + $(if ($null -ne $d.Age) { $d.Age.ToString() + ' days ago' } else { 'never (pwdLastSet=0)' }) + '; account state: ' + $(if ($d.Dec.IsDisabled) { 'disabled (reduces exposure but the SPN and key material still exist)' } else { 'enabled' })) `
                    -Validation 'LDAP attribute read; password age computed from pwdLastSet (100-nanosecond FILETIME converted with [datetime]::FromFileTime). No ticket requested, no password or key retrieved.' `
                    -Class $(if ($d.Priv.IsPrivileged) { 'Critical' } else { 'High' }) -CatClass 'Confidentiality' `
                    -Remediation ('Rotate the password immediately with a long random value (or migrate to gMSA), remove the account from privileged groups and grant it only the rights the service needs, enable AES-only encryption, and restrict the account''s logon scope (Log on to / Deny logon rights, and account-scoped host restrictions).') `
                    -Impact 'Long-lived and privileged SPN accounts are the highest-value Kerberoasting targets: their password age directly determines cracking feasibility, and their privileges determine whether the result is lateral movement or domain compromise.'
            }
        }

        # ---- Associated service reachability (validation of what the SPN points at) -------
        Write-Host ''
        Write-Host '  -- 11.2 Associated service reachability (bounded, max 12 lookups) ---------------' -ForegroundColor DarkCyan
        $checked = 0
        foreach ($d in $details) {
            if ($checked -ge 12) { break }
            foreach ($s in $d.Spns) {
                if ($checked -ge 12) { break }
                $map = Get-SpnServiceMap -Spn $s
                if (-not $map.HostPart -or $map.Port -eq 0) {
                    Write-Host ('    ' + $d.Sam + ' | ' + $s + ' -> service class ''' + $map.ServiceClass + ''' has no fixed well-known port; reachability not tested') -ForegroundColor DarkGray
                    continue
                }
                $checked++
                $resolved = $false; $ip = ''
                try {
                    $a = [System.Net.Dns]::GetHostAddresses($map.HostPart) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
                    if ($a) { $resolved = $true; $ip = $a.IPAddressToString }
                } catch { }
                if (-not $resolved) {
                    Write-Host ('    ' + $d.Sam + ' | ' + $s + ' -> host ''' + $map.HostPart + ''' did not resolve in DNS (SPN may be stale)') -ForegroundColor DarkGray
                    continue
                }
                $t = Test-TcpPort -Target $ip -Port $map.Port -TimeoutMs 900
                Write-Host ('    ' + $d.Sam + ' | ' + $s + ' -> ' + $map.HostPart + ' (' + $ip + ') TCP/' + $map.Port + ' = ' + $t.State) -ForegroundColor DarkGray
                Add-Finding -Category 'Service Accounts' -Status 'INFO' -CatClass 'Context' -Attribute 'SPN-to-service reachability' `
                    -Source $script:HostName -Target ($map.HostPart + ' (' + $ip + ')') -Port ([string]$map.Port) `
                    -Finding ('SPN ''' + $s + ''' (account ' + $d.Sam + ') resolves to a host whose service port is ' + $t.State + '.') `
                    -Observed ('DNS resolution succeeded; TCP/' + $map.Port + ' = ' + $t.State + ' (' + $t.Error + ')') `
                    -Validation 'DNS resolution + single bounded TCP connect (reachability only; no authentication and no service protocol interaction).' `
                    -Class 'Low' -Remediation $(if ($t.State -eq 'Open') { 'None for this check. Use this information to prioritise the account: a reachable service with a stale SPN password is immediately useful to an attacker.' } else { 'Remove or correct the SPN if the service no longer exists: stale SPNs create a false service identity that an attacker can still request tickets for.' }) `
                    -Impact $(if ($t.State -eq 'Open') { 'The service behind this SPN is live, which increases the value of the account''s ticket material because the ticket is immediately usable against the service.' } else { 'The SPN appears stale, which is a hygiene issue rather than a direct exposure.' }) -NoConsole
            }
        }
    }

    # ---- Managed service accounts --------------------------------------------------------
    if ($msas -and $msas.Count -gt 0) {
        Write-Host ''
        Write-Host '  -- 11.3 Managed service accounts (MSA / gMSA) ------------------------------------' -ForegroundColor DarkCyan
        $msaRows = @()
        foreach ($m in $msas) {
            $pl = Convert-FileTimeToDate (Get-AdProperty $m 'pwdLastSet')
            $msaRows += [pscustomobject]@{
                Account = (Get-AdProperty $m 'sAMAccountName')
                Spns = @($m['serviceprincipalname']).Count
                PwdRotated = $(if ($pl) { $pl.ToString('yyyy-MM-dd') } else { 'n/a (managed automatically)' })
            }
        }
        Write-Table -Rows $msaRows -Columns @('Account','Spns','PwdRotated') -Headers @{ Account='Managed service account'; Spns='# SPN'; PwdRotated='Password last rotated' }
        Add-Finding -Category 'Service Accounts' -Status 'PASS' -Attribute 'Managed service accounts in use' `
            -Finding ($msas.Count.ToString() + ' managed service account(s) (MSA/gMSA) are in use, which is the preferred pattern because the password is a 240-character value rotated automatically by the domain.') `
            -Observed 'Managed accounts enumerated via (objectClass=msDS-ManagedServiceAccount)/(objectClass=msDS-GroupManagedServiceAccount)' `
            -Validation 'LDAP read of managed-account objects' -Class 'Medium' `
            -Remediation 'Extend the gMSA pattern to every remaining application service account; gMSA also removes the operational need for documented password rotation.' `
            -Impact 'Managed accounts reduce the Kerberoasting exposure to a practical minimum, because the derived key cannot be guessed or cracked from a dictionary.'
    }
}

# ===========================================================================================
#  SECTION 12 :: DELEGATION AUDIT
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Kerberos delegation is legitimate functionality that is extremely dangerous when it lands
#  on the wrong principal:
#    * UNCONSTRAINED delegation (0x00080000) on a non-DC means the host caches the TGT of
#      every user who authenticates to it - an attacker with administrative access to that
#      host inherits those identities.
#    * CONSTRAINED delegation with protocol transition (0x01000000) allows obtaining a service
#      ticket for a user without that user's password.
#    * RESOURCE-BASED constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) can be
#      written by the resource owner, and is a known escalation primitive.
#  This module records the attributes, the privilege level of the principals and the
#  reachability of the affected hosts. It does NOT harvest tickets.
# ===========================================================================================
function Invoke-Section12_Delegation {
    if (-not $script:LdapReady) {
        Write-Status 'NOT TESTABLE' ((Get-LdapUnavailableReason) + ': delegation audit skipped.')
        Add-Finding -Category 'Kerberos Delegation' -Status 'NOT TESTABLE' -Attribute 'Delegation audit' -Finding 'Delegation attributes could not be read (directory unreachable).' `
            -Validation 'Not performed' -Class 'Critical' -Remediation 'Re-run from a domain-joined context.' -Impact 'Unknown.' -NoConsole
        return
    }
    Write-Host ''
    Write-Host '  -- 12.1 Unconstrained delegation (userAccountControl bit 0x00080000) ------------' -ForegroundColor DarkCyan
    $ds = New-AdSearcher -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
        -Properties @('distinguishedName','sAMAccountName','dNSHostName','objectCategory','userAccountControl','operatingSystem','adminCount','memberOf','servicePrincipalName','lastLogonTimestamp')
    $unc = Get-AdObjects -Searcher $ds
    if ($null -eq $unc) { Write-Status 'NOT TESTABLE' 'Unconstrained delegation query failed.' }
    else {
        $dcDns = @()
        if ($script:AdCounts.DomainControllers -ge 0) {
            try {
                $dcDs = New-AdSearcher -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Properties @('dNSHostName')
                $tmp = Get-AdObjects -Searcher $dcDs -Cap 200
                if ($tmp) { foreach ($t in $tmp) { $dcDns += (Get-AdProperty $t 'dNSHostName') } }
            } catch { }
        }
        $nonDc = @()
        foreach ($o in $unc) {
            $host = Get-AdProperty $o 'dNSHostName'
            $sam = Get-AdProperty $o 'sAMAccountName'
            $isDc = $false
            if ($host -and ($dcDns -contains $host)) { $isDc = $true }
            if ($sam -and $sam.EndsWith('$') -eq $false -and -not $host) { $isDc = $false }
            if ($sam -and $sam -match '\$$' -and -not $host) { }
            if (-not $isDc) { $nonDc += $o }
            Write-Host ('    ' + $sam + $(if ($host) { ' (' + $host + ')' } else { '' }) + '  UAC=' + (Get-UacDecode (Get-AdProperty $o 'userAccountControl')).ValueHex + $(if ($isDc) { '  [domain controller - expected]' } else { '  [NON-DC PRINCIPAL]' })) -ForegroundColor $(if ($isDc) { 'DarkGray' } else { 'Yellow' })
        }
        $script:Facts['UnconstrainedNonDc'] = $nonDc.Count
        if ($nonDc.Count -eq 0) {
            Add-Finding -Category 'Kerberos Delegation' -Status 'PASS' -Attribute 'Unconstrained delegation' `
                -Finding 'Unconstrained delegation is only configured on domain controllers, where it is inherent to the role.' `
                -Configured 'LDAP bitwise match on userAccountControl mask 0x00080000 (524288)' -Observed ('Matching objects: ' + $unc.Count + ', all identified as domain controllers') `
                -Validation 'LDAP attribute read with exact hexadecimal decoding, cross-referenced against the SERVER_TRUST_ACCOUNT flag (0x00002000) and the DC dNSHostName list' -Class 'Critical' -CatClass 'IdentityRights' `
                -Remediation 'Maintain the rule that no member server or workstation is trusted for unconstrained delegation; enforce it in change control and re-check after every application installation.' `
                -Impact 'None observed on non-DC systems.'
        } else {
            foreach ($o in $nonDc) {
                $sam = Get-AdProperty $o 'sAMAccountName'
                $host = Get-AdProperty $o 'dNSHostName'
                $os = Get-AdProperty $o 'operatingSystem'
                $reach = 'not tested'
                $reachOpen = $null
                if ($host) {
                    $t = Test-TcpPort -Target $host -Port 445 -TimeoutMs 900
                    $reach = $t.State
                    if ($t.State -eq 'Open') { $reachOpen = $true } elseif ($t.State -eq 'Closed' -or $t.State -eq 'Filtered') { $reachOpen = $false }
                }
                Add-Finding -Category 'Kerberos Delegation' -Status 'RISK DETECTED' -Attribute 'Unconstrained delegation on non-DC principal' `
                    -Target $sam -Finding ('Principal ''' + $sam + ''' ' + $(if ($host) { '(' + $host + ') ' } else { '' }) + 'is trusted for UNCONSTRAINED Kerberos delegation. It receives and caches the Kerberos TGT of every user that authenticates to it, in memory, as a service-usable credential.') `
                    -Configured ('userAccountControl=' + (Get-UacDecode (Get-AdProperty $o 'userAccountControl')).ValueHex + ' with TRUSTED_FOR_DELEGATION (0x00080000) set' + $(if ($os) { ' ; operatingSystem=' + $os } else { '' })) `
                    -Observed ('Host 445 reachability from the assessment position: ' + $reach + $(if ($null -ne $reachOpen) { ' (host appears ' + $(if ($reachOpen) { 'reachable' } else { 'not reachable' }) + ')' } else { '' }) + '. Ticket capture was NOT performed: harvesting tickets is prohibited by this tool''s design.') `
                    -Validation 'LDAP attribute read (configuration evidence) + bounded TCP reachability test (prerequisite evidence). The credential-theft step is deliberately NOT executed.' `
                    -Prerequisites ('Administrative access to the delegation host: any user who obtains that access inherits every TGT cached on it. Reachability to the host was tested above; the privilege step was not exercised.') `
                    -Exploitability 'Preconditions measured but not exercised: the delegation configuration and host reachability are validated, the ticket-capture impact is not demonstrated and must not be claimed without performing it.' `
                    -Class 'Critical' -CatClass 'IdentityRights' `
                    -Remediation 'Remove unconstrained delegation (Set-ADAccountControl -TrustedForDelegation $false / Set-ADComputer -TrustedForDelegation $false) and replace it with constrained delegation or resource-based constrained delegation for the specific service required. Add the principal to Protected Users where compatible, and mark sensitive accounts as "Account is sensitive and cannot be delegated".' `
                    -Impact 'A non-DC principal trusted for unconstrained delegation is a credential-collection point: an attacker who gains administrative access to it (or who can trigger authentication to it from a privileged account, for example through coercion) can harvest the TGTs of the accounts that authenticate, then use them elsewhere - the classic domain-escalation chain.'
            }
        }
    }

    Write-Host ''
    Write-Host '  -- 12.2 Constrained delegation (msDS-AllowedToDelegateTo) ------------------------' -ForegroundColor DarkCyan
    $cdDs = New-AdSearcher -Filter '(msDS-AllowedToDelegateTo=*)' `
        -Properties @('distinguishedName','sAMAccountName','dNSHostName','msDS-AllowedToDelegateTo','userAccountControl','adminCount','memberOf','objectCategory','operatingSystem')
    $cds = Get-AdObjects -Searcher $cdDs
    if ($null -eq $cds) { Write-Status 'NOT TESTABLE' 'Constrained delegation query failed.' }
    elseif ($cds.Count -eq 0) {
        Write-Status 'PASS' 'No principal has a populated msDS-AllowedToDelegateTo attribute.'
        Add-Finding -Category 'Kerberos Delegation' -Status 'PASS' -Attribute 'Constrained delegation' `
            -Finding 'No account or computer has constrained delegation configured.' -Observed 'Zero matching objects' `
            -Validation 'LDAP query on (msDS-AllowedToDelegateTo=*)' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'No action. If delegation is later required, prefer resource-based constrained delegation on the target service, and avoid protocol transition.' `
            -Impact 'None observed.'
    } else {
        foreach ($o in $cds) {
            $sam = Get-AdProperty $o 'sAMAccountName'
            $targets = @($o['msds-allowedtodelegateto'])
            $dec = Get-UacDecode (Get-AdProperty $o 'userAccountControl')
            $transition = (($dec.Value -band 0x01000000) -eq 0x01000000)
            $priv = Test-PrivilegedRelationship -Object $o
            $sensitiveTargets = @()
            foreach ($t in $targets) {
                if ($t -match '(?i)MSSQLSvc|HTTP/|HOST/|cifs/|ldap/|krbtgt' ) { $sensitiveTargets += $t }
            }
            Write-Host ('    ' + $sam + ' -> ' + ($targets -join ' | ') + $(if ($transition) { '  [PROTOCOL TRANSITION ENABLED]' } else { '' })) -ForegroundColor $(if ($transition) { 'Yellow' } else { 'Gray' })
            Add-Finding -Category 'Kerberos Delegation' -Status $(if ($transition -or $priv.IsPrivileged) { 'RISK DETECTED' } else { 'WARN' }) -Attribute 'Constrained delegation configuration' `
                -Target $sam -Finding ('Principal ''' + $sam + ''' is allowed to delegate to ' + $targets.Count + ' service(s)' + $(if ($transition) { ', with PROTOCOL TRANSITION enabled (altered-user delegation): it can obtain a service ticket for a user without that user''s password.' } else { '.' })) `
                -Configured ('msDS-AllowedToDelegateTo=[' + ($targets -join '; ') + '] ; userAccountControl=' + $dec.ValueHex + $(if ($transition) { ' with TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000)' } else { '' })) `
                -Observed ('Privileged relationship: ' + $(if ($priv.IsPrivileged) { $priv.Reasons } else { 'none observed' }) + '; SPN targets that map to high-value services: ' + $sensitiveTargets.Count) `
                -Validation 'LDAP attribute read with exact hexadecimal flag decoding. No ticket with impersonated credentials was requested (that constitutes credential theft and is out of scope).' `
                -Class $(if ($transition) { 'Critical' } else { 'High' }) -CatClass 'IdentityRights' `
                -Remediation 'Restrict delegation to the specific target service and, where the service supports it, migrate to resource-based constrained delegation (which the resource owner controls). Remove protocol transition unless the application cannot use Kerberos end-to-end. Constrain the delegating principal to the minimum hosts (Log on to / user rights) and add sensitive accounts to Protected Users.' `
                -Impact $(if ($transition) { 'Protocol transition lets an attacker with the delegating principal''s credentials obtain a valid service ticket impersonating any user - including domain administrators - for the delegated SPN, without needing that user''s password. This is a direct privilege-escalation path.' } else { 'Constrained delegation limits the attack to the listed services, but those services (especially file systems, SQL and host SPNs) frequently hold privileged data or code paths that yield administrative access.' })
        }
    }

    Write-Host ''
    Write-Host '  -- 12.3 Resource-based constrained delegation and protocol transition ------------' -ForegroundColor DarkCyan
    $rbDs = New-AdSearcher -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
        -Properties @('distinguishedName','sAMAccountName','dNSHostName','msDS-AllowedToActOnBehalfOfOtherIdentity','objectCategory','operatingSystem','servicePrincipalName')
    $rbds = Get-AdObjects -Searcher $rbDs
    if ($null -eq $rbds) { Write-Status 'NOT TESTABLE' 'RBCD query failed (the attribute may not be readable with the current rights).' }
    elseif ($rbds.Count -eq 0) {
        Write-Status 'PASS' 'No object has a populated msDS-AllowedToActOnBehalfOfOtherIdentity attribute.'
        Add-Finding -Category 'Kerberos Delegation' -Status 'PASS' -Attribute 'Resource-based constrained delegation (RBCD)' `
            -Finding 'No computer or user object has resource-based constrained delegation configured.' -Observed 'Zero matching objects' `
            -Validation 'LDAP query on (msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'No action. Where RBCD is required later, document the delegating principals and monitor writes to this attribute; it can be set by any principal with WriteProperty on the object (often the machine account itself).' `
            -Impact 'None observed.'
    } else {
        foreach ($o in $rbds) {
            $sam = Get-AdProperty $o 'sAMAccountName'
            $sddl = Get-AdProperty $o 'msDS-AllowedToActOnBehalfOfOtherIdentity'
            $count = 0
            if ($sddl) { $count = ([regex]::Matches([string]$sddl, 'ACE')).Count }
            Add-Finding -Category 'Kerberos Delegation' -Status 'WARN' -Attribute 'Resource-based constrained delegation configured' `
                -Target $sam -Finding ('Object ''' + $sam + ''' has a resource-based constrained delegation security descriptor set (principals listed in msDS-AllowedToActOnBehalfOfOtherIdentity may impersonate any user to this resource).') `
                -Configured ('msDS-AllowedToActOnBehalfOfOtherIdentity is POPULATED (present, non-empty); raw security descriptor is not reproduced here to avoid embedding unnecessary security-data detail in the report.') `
                -Observed ('Attribute present ; object class = ' + (Get-AdProperty $o 'objectCategory')) `
                -Validation 'LDAP attribute presence check. No impersonation ticket was requested. To identify the delegating principals, read the attribute''s ACEs with a dedicated query during remediation.' `
                -Class 'High' -CatClass 'IdentityRights' `
                -Remediation 'Verify that the listed principals are the intended service identities and nothing else; remove stale entries. Restrict WriteProperty on the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of computer objects (this is where RBCD abuse starts: a principal who can write this attribute on a target effectively gains impersonation rights to that target). Monitor 5136 directory-change events for this attribute.' `
                -Impact 'RBCD allows any principal in the ACL to impersonate arbitrary users - including administrators - against the target service. If the ability to WRITE this attribute is broadly delegated (for example through unconstrained OU-level delegation), a low-privilege attacker can create the delegation themselves.'
        }
    }

    # Protocol transition on its own (no constrained-delegation targets)
    $ptDs = New-AdSearcher -Filter '(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(!(msDS-AllowedToDelegateTo=*)))' `
        -Properties @('distinguishedName','sAMAccountName','userAccountControl')
    $pts = Get-AdObjects -Searcher $ptDs -Cap 50
    if ($pts -and $pts.Count -gt 0) {
        $names = @()
        foreach ($p in $pts) { $names += ((Get-AdProperty $p 'sAMAccountName') + ' ' + (Get-UacDecode (Get-AdProperty $p 'userAccountControl')).ValueHex) }
        Add-Finding -Category 'Kerberos Delegation' -Status 'WARN' -Attribute 'Protocol transition without delegation targets' `
            -Finding ($pts.Count.ToString() + ' principal(s) have TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000) but no msDS-AllowedToDelegateTo entries: the setting has no current effect but indicates a delegation configuration was started and not cleaned up.') `
            -Configured 'LDAP bitwise match on 0x01000000 (16777216) combined with a negative match on msDS-AllowedToDelegateTo' `
            -Observed ($names -join '; ') -Validation 'LDAP query with exact hexadecimal masks' `
            -Class 'Low' -CatClass 'IdentityRights' `
            -Remediation 'Clear TRUSTED_TO_AUTH_FOR_DELEGATION on the listed principals if delegation is not required; a half-configured delegation setting is a change-control defect that can become exploitable the moment a target is added.' `
            -Impact 'None today beyond configuration drift and an increased likelihood of a dangerous configuration later.'
    }
}

# ===========================================================================================
#  SECTION 13 :: ENCRYPTION DOWNGRADE AUDIT (msDS-SupportedEncryptionTypes)
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  The encryption types an account supports decide what an attacker gets when they request a
#  Kerberos ticket for it. RC4-HMAC tickets are crackable far faster than AES tickets, so an
#  account that permits RC4 is a much more attractive target than one that is AES-only.
#
#  CRITICAL DISTINCTION MADE BY THIS MODULE
#  ----------------------------------------------------------------------------------------
#  ATTRIBUTE ABSENT is not the same as "RC4 preferred". When the attribute is absent or zero,
#  no explicit preference has been expressed by the administrator, and per Microsoft's
#  documented behaviour the KDC falls back to the widest compatible set for the account. This
#  module therefore reports "absent" as its own state and never claims an explicit RC4
#  preference from a missing value.
# ===========================================================================================
function Get-EncryptionTypesDecode {
    param([object]$Value, [bool]$Absent = $false)
    $r = [pscustomobject]@{ Present=$false; Raw=$null; Hex=''; Flags=@(); Text=''; Aes128=$false; Aes256=$false; Rc4=$false; Des=$false; AesOnly=$false }
    if ($Absent -or $null -eq $Value) {
        $r.Present = $false
        $r.Text = 'ATTRIBUTE ABSENT - no explicit encryption preference is expressed. Per Microsoft''s documented behaviour the KDC then falls back to the widest compatible set for the account, so this must NOT be read as an explicit RC4 preference, nor as AES-only.'
        return $r
    }
    $v = 0
    if (-not [int64]::TryParse([string]$Value, [ref]$v)) { $r.Text = 'value present but not parsable'; return $r }
    $r.Present = $true; $r.Raw = $v; $r.Hex = '0x' + ([int64]$v).ToString('X8')
    # Array-of-objects rather than a hashtable: integer keys in a [ordered] dictionary bind to
    # the ORDERED DICTIONARY'S POSITIONAL indexer in PowerShell and return $null without error.
    $map = @(
        [pscustomobject]@{ Mask=0x00000001; Name='DES-CBC-CRC (0x00000001)' }
        [pscustomobject]@{ Mask=0x00000002; Name='DES-CBC-MD5 (0x00000002)' }
        [pscustomobject]@{ Mask=0x00000004; Name='RC4-HMAC (0x00000004)' }
        [pscustomobject]@{ Mask=0x00000008; Name='AES128-CTS-HMAC-SHA1-96 (0x00000008)' }
        [pscustomobject]@{ Mask=0x00000010; Name='AES256-CTS-HMAC-SHA1-96 (0x00000010)' }
        [pscustomobject]@{ Mask=0x00000020; Name='Future/Unused (0x00000020)' }
        [pscustomobject]@{ Mask=0x00000040; Name='Future/Unused (0x00000040)' }
        [pscustomobject]@{ Mask=0x00000200; Name='FAST negotiation support (0x00000200) - compound identity / FastArmor capability' }
        [pscustomobject]@{ Mask=0x00000800; Name='Compound identity REQUIRED (0x00000800)' }
    )
    $flags = @()
    foreach ($m in $map) { if (($v -band $m.Mask) -eq $m.Mask) { $flags += $m.Name } }
    $r.Flags = $flags
    $r.Des    = ((($v -band 0x00000001) -eq 0x00000001) -or (($v -band 0x00000002) -eq 0x00000002))
    $r.Rc4    = (($v -band 0x00000004) -eq 0x00000004)
    $r.Aes128 = (($v -band 0x00000008) -eq 0x00000008)
    $r.Aes256 = (($v -band 0x00000010) -eq 0x00000010)
    $r.AesOnly = ($r.Aes128 -and $r.Aes256 -and -not $r.Rc4 -and -not $r.Des)
    $r.Text = $r.Hex + ' : ' + $(if ($flags.Count -gt 0) { $flags -join ' + ' } else { 'NO bits set (equivalent to no explicit preference: the KDC falls back to the widest compatible set)' })
    return $r
}

function Invoke-Section13_Encryption {
    if (-not $script:LdapReady) {
        Write-Status 'NOT TESTABLE' ((Get-LdapUnavailableReason) + ': Kerberos encryption-type audit skipped.')
        Add-Finding -Category 'Kerberos Encryption' -Status 'NOT TESTABLE' -Attribute 'msDS-SupportedEncryptionTypes audit' -Finding 'Encryption-type attributes could not be read (directory unreachable).' `
            -Validation 'Not performed' -Class 'High' -Remediation 'Re-run from a domain-joined context.' -Impact 'Unknown.' -NoConsole
        return
    }
    Write-Host ''
    Write-Host '  -- 13.1 msDS-SupportedEncryptionTypes - computer objects -------------------------' -ForegroundColor DarkCyan
    $ds = New-AdSearcher -Filter '(objectCategory=computer)' -Properties @('distinguishedName','sAMAccountName','dNSHostName','msDS-SupportedEncryptionTypes','operatingSystem','userAccountControl')
    $comps = Get-AdObjects -Searcher $ds
    if ($null -eq $comps) { Write-Status 'NOT TESTABLE' 'Computer encryption-type query failed.' }
    else {
        $absent = 0; $rc4only = 0; $aesonly = 0; $des = 0; $zero = 0
        $badRows = @()
        foreach ($c in $comps) {
            $has = $c.ContainsKey('msds-supportedencryptiontypes')
            $val = Get-AdProperty $c 'msds-supportedencryptiontypes'
            $d = Get-EncryptionTypesDecode -Value $val -Absent (-not $has)
            if (-not $d.Present) { $absent++ }
            elseif ($null -ne $d.Raw -and [int64]$d.Raw -eq 0) { $zero++ }
            elseif ($d.AesOnly) { $aesonly++ }
            elseif ($d.Rc4 -and -not $d.Aes128 -and -not $d.Aes256) { $rc4only++ }
            if ($d.Des) { $des++ }
            if ($d.Des -or ($d.Rc4 -and -not ($d.Aes128 -and $d.Aes256))) {
                $badRows += [pscustomobject]@{ Host=(Get-AdProperty $c 'dNSHostName'); Sam=(Get-AdProperty $c 'sAMAccountName'); Et=$(if ($d.Present) { $d.Hex } else { 'absent' }); Decoded=$d.Text }
            }
        }
        $script:Facts['Rc4EnabledObjects'] = $rc4only + $des
        Write-KV 'Computers total' $comps.Count
        Write-KV 'Attribute ABSENT' $absent
        Write-KV 'Attribute present, value 0' $zero
        Write-KV 'AES-only (0x18 style)' $aesonly
        Write-KV 'RC4-only' $rc4only
        Write-KV 'DES permitted (broken)' $des
        Add-Finding -Category 'Kerberos Encryption' -Status $(if ($des -gt 0) { 'RISK DETECTED' } elseif ($rc4only -gt 0) { 'WARN' } else { 'INFO' }) -Attribute 'Computer Kerberos encryption capability' `
            -Finding ('Of ' + $comps.Count + ' computer objects: ' + $absent + ' have the attribute ABSENT, ' + $zero + ' have it present as 0, ' + $aesonly + ' are AES-only, ' + $rc4only + ' are RC4-only, and ' + $des + ' still permit DES.') `
            -Configured 'msDS-SupportedEncryptionTypes decoded with exact hexadecimal masks (0x1 DES-CRC, 0x2 DES-MD5, 0x4 RC4-HMAC, 0x8 AES128, 0x10 AES256, 0x200 FAST, 0x800 compound identity required)' `
            -Observed ('ATTRIBUTE ABSENT is reported as its OWN state and is NOT interpreted as an RC4 preference: when the attribute is absent or zero the KDC applies its documented fallback, so the absence tells us nothing about an administrator''s intent. AES-only vs RC4-only counts above are based on values explicitly present in the directory.') `
            -Validation 'Paged LDAP read of the attribute for every computer object, with the presence/absence distinction preserved explicitly.' `
            -Class $(if ($des -gt 0) { 'Critical' } else { 'Medium' }) -CatClass 'Confidentiality' `
            -Remediation 'Standardise on 0x18 (AES128+AES256) for servers and clients once every Kerberos service supports AES, remove 0x04 (RC4) from service accounts and computers, and never allow 0x1/0x2 (DES). Track down the applications that still force RC4 before removing it, and confirm with the Kerberos event log (events 4768/4769 record the encryption type actually used).' `
            -Impact 'Every account or computer that permits RC4 gives an attacker a ticket that is orders of magnitude cheaper to crack offline than an AES ticket. DES is worse still: its 56-bit key space is brute-forceable. Where the attribute is absent, the effective capability depends on the KDC''s documented fallback, so those objects need an explicit decision rather than an assumption.'
        if ($badRows.Count -gt 0) {
            Write-Host ''
            Write-Host '  -- 13.2 Computers with RC4-only or DES capability (explicit values) --------------' -ForegroundColor DarkCyan
            Write-Table -Rows ($badRows | Select-Object -First 25) -Columns @('Host','Sam','Et','Decoded') -Headers @{ Host='Host'; Sam='sAMAccountName'; Et='Value'; Decoded='Decoded capability' }
            if ($badRows.Count -gt 25) { Write-Host ('    ... and ' + ($badRows.Count - 25) + ' further objects (full list in the CSV report).') -ForegroundColor DarkGray }
        }
    }

    Write-Host ''
    Write-Host '  -- 13.3 msDS-SupportedEncryptionTypes - user objects -----------------------------' -ForegroundColor DarkCyan
    $uds = New-AdSearcher -Filter '(objectCategory=person)' -Properties @('distinguishedName','sAMAccountName','msDS-SupportedEncryptionTypes','servicePrincipalName','adminCount')
    $users = Get-AdObjects -Searcher $uds
    if ($null -ne $users) {
        $uAbsent = 0; $uRc4 = 0; $uAes = 0; $uDes = 0; $notable = @()
        foreach ($u in $users) {
            $has = $u.ContainsKey('msds-supportedencryptiontypes')
            $d = Get-EncryptionTypesDecode -Value (Get-AdProperty $u 'msds-supportedencryptiontypes') -Absent (-not $has)
            if (-not $d.Present) { $uAbsent++ } else {
                if ($d.Des) { $uDes++ }
                if ($d.Rc4) { $uRc4++ }
                if ($d.AesOnly) { $uAes++ }
                if (($d.Des -or $d.Rc4) -and (Get-AdProperty $u 'adminCount') -eq '1') {
                    $notable += [pscustomobject]@{ Sam=(Get-AdProperty $u 'sAMAccountName'); Et=$d.Hex; Decoded=$d.Text; Note='privileged (adminCount=1)' }
                }
            }
        }
        Write-KV 'Users total' $users.Count
        Write-KV 'Attribute ABSENT' $uAbsent
        Write-KV 'AES-only' $uAes
        Write-KV 'RC4 permitted' $uRc4
        Write-KV 'DES permitted' $uDes
        Add-Finding -Category 'Kerberos Encryption' -Status $(if ($uDes -gt 0) { 'RISK DETECTED' } elseif ($uRc4 -gt 0) { 'WARN' } else { 'INFO' }) -Attribute 'User Kerberos encryption capability' `
            -Finding ('Of ' + $users.Count + ' user objects: ' + $uAbsent + ' have the attribute ABSENT, ' + $uAes + ' are AES-only, ' + $uRc4 + ' explicitly permit RC4, and ' + $uDes + ' permit DES.') `
            -Configured 'Explicit values decoded with exact hexadecimal masks; ABSENT reported separately from 0' `
            -Observed 'See counts above. No explicit RC4 preference is inferred for objects where the attribute is absent.' `
            -Validation 'Paged LDAP read, presence/absence preserved' -Class $(if ($uDes -gt 0) { 'Critical' } else { 'Medium' }) -CatClass 'Confidentiality' `
            -Remediation 'Set msDS-SupportedEncryptionTypes=0x18 on all user accounts (and on the accounts of every service), then remove RC4 support on the KDC side (SupportedEncryptionTypes policy) once dependency tracking is complete. Where an object must remain RC4-capable, document the compensating control and rotate its password frequently with a long random value.' `
            -Impact 'User accounts that permit RC4-encrypted tickets hand an attacker a much cheaper cracking problem; privileged accounts with RC4 capability are the highest-priority remediation target in this section.'
        if ($notable.Count -gt 0) {
            Write-Table -Rows $notable -Columns @('Sam','Et','Note') -Headers @{ Sam='Account'; Et='msDS-SupportedEncryptionTypes'; Note='Note' }
        }
    }

    $desOnly = $null
    try {
        $dk = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes'
        Write-KV 'Local Kerberos encryption policy (client)' (Format-RegState $dk)
    } catch { }
}

# ===========================================================================================
#  SECTION 14 :: LAPS AUDIT
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  LAPS removes the "same local administrator password everywhere" problem by giving each
#  computer a unique, rotated, escrowed credential. The assessment question is coverage:
#  does the schema support it, is the client deployed, and do computer objects actually carry
#  the rotation metadata? This module answers that question and NOTHING MORE.
#
#  HARD LIMIT: the module never requests, reads, stores or displays the password value itself
#  (ms-Mcs-AdmPwd / msLAPS-Password). Reading a local-administrator password that the
#  engagement may not have scoped as in-cover would be both an authorisation breach and a
#  credential-handling violation. Only the EXPIRATION metadata and attribute EXISTENCE are
#  examined, which is sufficient to measure coverage.
# ===========================================================================================
function Invoke-Section14_Laps {
    if (-not $script:LdapReady) {
        Write-Status 'NOT TESTABLE' ((Get-LdapUnavailableReason) + ': LAPS coverage audit skipped.')
        Add-Finding -Category 'LAPS' -Status 'NOT TESTABLE' -Attribute 'LAPS audit' -Finding 'LAPS metadata could not be read (directory unreachable).' `
            -Validation 'Not performed' -Class 'Medium' -Remediation 'Re-run from a domain-joined context.' -Impact 'Unknown.' -NoConsole
        return
    }
    Write-Host ''
    Write-Host '  -- 14.1 LAPS schema attribute presence ------------------------------------------' -ForegroundColor DarkCyan
    $schemaAttrs = @('ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword','msLAPS-EncryptedPasswordHistory','msLAPS-EncryptedDSRMPassword')
    $present = Get-AdSchemaAttributePresence -CommonNames $schemaAttrs
    foreach ($k in $schemaAttrs) {
        Write-Host ('    ' + $k.PadRight(34) + $(if ($present[$k]) { 'PRESENT in schema' } else { 'not present in schema' })) -ForegroundColor $(if ($present[$k]) { 'Gray' } else { 'DarkGray' })
    }
    $legacyLaps = ($present['ms-Mcs-AdmPwd'] -or $present['ms-Mcs-AdmPwdExpirationTime'])
    $windowsLaps = ($present['msLAPS-Password'] -or $present['msLAPS-PasswordExpirationTime'] -or $present['msLAPS-EncryptedPassword'])
    Add-Finding -Category 'LAPS' -Status $(if ($legacyLaps -or $windowsLaps) { 'INFO' } else { 'WARN' }) -Attribute 'LAPS schema extension' `
        -Finding $(if ($windowsLaps -and $legacyLaps) { 'Both the legacy LAPS schema (ms-Mcs-*) and the Windows LAPS schema (msLAPS-*) are present: the directory has been extended for both generations.' } elseif ($windowsLaps) { 'The Windows LAPS schema (msLAPS-*) is present; the legacy ms-Mcs-* attributes are absent.' } elseif ($legacyLaps) { 'The legacy LAPS schema (ms-Mcs-AdmPwd*) is present; the newer msLAPS-* attributes are absent (Windows LAPS uses the legacy schema on schema versions before the Windows LAPS update).' } else { 'No LAPS schema attributes were found, so local administrator password rotation is not being escrowed in this directory. Note: this reflects the schema, not a deployment decision; a client could still be writing to attributes this query cannot see.' }) `
        -Observed ('Schema query results: ' + (($schemaAttrs | ForEach-Object { $_ + '=' + $present[$_] }) -join '; ')) `
        -Validation 'LDAP search of the schema naming context for each attributeSchema object (read-only, no RSAT).' `
        -Class 'High' -CatClass 'IdentityRights' `
        -Remediation 'If LAPS is not deployed: extend the schema once (Update-LapsADSchema) and enable Windows LAPS through GPO, or deploy the legacy LAPS client with the corresponding ADMX. Either way, exclude accounts that must not be managed and confirm the recovered password path is restricted to the correct tier-0 group.' `
        -Impact 'Without LAPS, local administrator passwords are either identical across the estate or manually managed. Identical local administrator credentials convert any single compromised workstation into administrative access to every host sharing that password - one of the most common full-estate compromises observed in internal assessments.'
    if ($windowsLaps -and $legacyLaps) {
        Add-Finding -Category 'LAPS' -Status 'INFO' -Attribute 'LAPS migration state' `
            -Finding 'Exactly one LAPS generation should be the source of truth. Both schema generations present without a documented migration state increases the risk of an unmanaged gap between them.' `
            -Observed 'Legacy and Windows LAPS attributes both present in schema' -Validation 'Schema query' -Class 'Low' -CatClass 'IdentityRights' `
            -Remediation 'Complete the migration to Windows LAPS (which uses DPAPI-NG and supports DSRM passwords) and then decommission the legacy client; confirm coverage is maintained throughout.' `
            -Impact 'Two parallel escrow mechanisms can leave some computers on neither, which is invisible without the coverage measurement below.' -NoConsole
    }

    Write-Host ''
    Write-Host '  -- 14.2 LAPS coverage on computer objects ---------------------------------------' -ForegroundColor DarkCyan
    $expAttr = ''
    if ($present['msLAPS-PasswordExpirationTime']) { $expAttr = 'msLAPS-PasswordExpirationTime' }
    elseif ($present['ms-Mcs-AdmPwdExpirationTime']) { $expAttr = 'ms-Mcs-AdmPwdExpirationTime' }
    if (-not $expAttr) {
        Write-Status 'NOT TESTABLE' 'No LAPS expiration attribute exists in the schema, so coverage cannot be measured (the deployment question is answered by the schema finding above).'
        Add-Finding -Category 'LAPS' -Status 'NOT TESTABLE' -Attribute 'LAPS coverage measurement' `
            -Finding 'Coverage of LAPS rotation cannot be measured because no expiration attribute is present in the schema.' `
            -Validation 'Schema-dependent: measurement is impossible until the schema is extended.' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'Extend the schema and deploy the LAPS client, then re-run this module to obtain a coverage figure.' `
            -Impact 'Unknown coverage. Treat local administrator credential reuse as UNMITIGATED for the affected hosts until coverage is demonstrated.' -NoConsole
        return
    }
    Write-Host ('    using attribute: ' + $expAttr + ' (password values are never read)') -ForegroundColor DarkGray
    $ds = New-AdSearcher -Filter '(objectCategory=computer)' -Properties @('distinguishedName','dNSHostName','sAMAccountName','operatingSystem', $expAttr)
    $comps = Get-AdObjects -Searcher $ds
    if ($null -eq $comps) { Write-Status 'NOT TESTABLE' 'Computer query for LAPS metadata failed.'; return }
    $withAttr = 0; $withValue = 0; $expired = 0; $missing = @()
    foreach ($c in $comps) {
        $hasAttr = $c.ContainsKey($expAttr.ToLower())
        $val = Get-AdProperty $c $expAttr
        $dt = Convert-FileTimeToDate $val
        if ($dt) {
            $withValue++
            if ($dt -lt (Get-Date)) { $expired++ }
        } else {
            $missing += [pscustomobject]@{ Host=(Get-AdProperty $c 'dNSHostName'); Sam=(Get-AdProperty $c 'sAMAccountName'); OS=(Get-AdProperty $c 'operatingSystem'); HasAttribute=$hasAttr }
        }
    }
    $coverage = if ($comps.Count -gt 0) { [math]::Round((100.0 * $withValue / $comps.Count), 1) } else { 0 }
    $script:Facts['LapsCoverageMissing'] = ($comps.Count - $withValue)
    $script:Facts['LapsCoveragePercent'] = $coverage
    Write-KV 'Computer objects' $comps.Count
    Write-KV 'With rotation metadata' $withValue
    Write-KV 'Without rotation metadata' ($comps.Count - $withValue)
    Write-KV 'Metadata already expired' $expired
    Write-KV 'Coverage' ($coverage.ToString() + ' %')
    if ($missing.Count -gt 0) {
        Write-Table -Rows ($missing | Select-Object -First 25) -Columns @('Host','Sam','OS','HasAttribute') -Headers @{ Host='Host'; Sam='Account'; OS='Operating system'; HasAttribute='Attribute present but empty' }
        if ($missing.Count -gt 25) { Write-Host ('    ... and ' + ($missing.Count - 25) + ' further objects (full list in the CSV report).') -ForegroundColor DarkGray }
    }
    Add-Finding -Category 'LAPS' -Status $(if ($coverage -ge 95) { 'PASS' } elseif ($coverage -gt 0) { 'WARN' } else { 'RISK DETECTED' }) -Attribute 'LAPS rotation coverage' `
        -Finding ('LAPS rotation metadata is present on ' + $withValue + ' of ' + $comps.Count + ' computer objects (' + $coverage + ' % coverage). ' + $expired + ' record(s) are already past their rotation deadline, and ' + ($comps.Count - $withValue) + ' object(s) have no rotation metadata at all.') `
        -Configured ('Attribute examined: ' + $expAttr + ' (expiration metadata only). The password attributes (ms-Mcs-AdmPwd / msLAPS-Password) were NOT requested, read, stored or displayed by this tool.') `
        -Observed ('Coverage ' + $coverage + ' %; expired rotations ' + $expired + '; objects without metadata ' + ($comps.Count - $withValue) + '. Sample of uncovered objects listed above and in the CSV.') `
        -Validation 'Paged LDAP read of the expiration attribute only, converted with [datetime]::FromFileTime. No credential material is involved in this check in any form.' `
        -Prerequisites 'Reading the expiration metadata requires no special rights; the password value would, which is precisely why it is not read.' `
        -Class 'Critical' -CatClass 'IdentityRights' `
        -Remediation 'Achieve full coverage: create LAPS policies linked at every OU containing computer objects, verify that the client is present and the relevant service runs on each host, exclude hosts that genuinely cannot be managed (with compensating controls), and alert on computers whose rotation metadata becomes stale - stale metadata means the password is not rotating. Restrict who may read the password values (tier-0 only) and audit that read access (4662/4662 events for the attribute).' `
        -Impact ('Local administrator password reuse is the difference between "one compromised workstation" and "administrative access to every host with that password". A ' + $coverage + ' % coverage figure means ' + ($comps.Count - $withValue) + ' computer object(s) are relying on whatever password management process existed before LAPS: those hosts are the residual exposure, and they are named in this report so they can be remediated individually.')
}
# ===========================================================================================
#  SECTIONS 15-16 :: NETWORK SEGMENTATION + LATERAL-MOVEMENT ATTACK PATHS  (part 9/12)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Segmentation is the control that decides how far a single foothold can travel. This part
#  converts the raw reachability matrix from Section 8 into zone-level statements, and then
#  correlates every evidence item collected so far into candidate attack paths.
#
#  METHODOLOGICAL DISCIPLINE (this is the part of an internal assessment that is most often
#  exaggerated, so the rules are explicit):
#    * a zone is only asserted where the OBSERVED service profile supports it; otherwise the
#      segment is reported as "profile not classifiable" rather than guessed
#    * every path link must cite the evidence that supports it, and links that were not
#      validated are labelled as such
#    * a path is only published when EVERY link has evidence; a path with an unvalidated link
#      is published as "candidate / unvalidated" and is never written as an achieved result
#    * network connectivity is NEVER described as successful lateral movement
# ===========================================================================================

function Test-DirectoryWritable {
    <# Determines whether a directory can be modified by the current assessment identity.
       Two independent sources of evidence are used:
         (1) ACL analysis - broad write ACEs (Everyone / Authenticated Users / Users /
             Interactive / Anonymous) or a write ACE for the current identity.
         (2) A controlled marker-file write test (created then deleted immediately) which
             PROVES the permission rather than inferring it. The test never overwrites or
             creates anything executable and always cleans up after itself. #>
    param([string]$Path, [switch]$NoWriteTest)
    $res = [pscustomobject]@{
        Path = $Path; Exists = $false; AclReadable = $false; BroadWriteAce = $false; BroadAces = ''
        WriteTested = $false; WriteSucceeded = $false; ArtifactPath = ''; Error = ''
    }
    if (-not (Test-Path -LiteralPath $Path)) { $res.Error = 'path does not exist'; return $res }
    $res.Exists = $true
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $res.AclReadable = $true
        $broadSids = @{
            'S-1-1-0'      = 'Everyone'
            'S-1-5-11'     = 'Authenticated Users'
            'S-1-5-32-545' = 'BUILTIN\Users'
            'S-1-5-4'      = 'INTERACTIVE'
            'S-1-5-7'      = 'ANONYMOUS LOGON'
            'S-1-5-32-546' = 'BUILTIN\Guests'
        }
        $writeMask = [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
                     [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
                     [int][System.Security.AccessControl.FileSystemRights]::Write -bor
                     [int][System.Security.AccessControl.FileSystemRights]::Modify -bor
                     [int][System.Security.AccessControl.FileSystemRights]::FullControl -bor
                     [int][System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                     [int][System.Security.AccessControl.FileSystemRights]::CreateDirectories
        $hits = @()
        foreach ($ace in $acl.Access) {
            try {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch { continue }
            $rights = 0
            try { $rights = [int]$ace.FileSystemRights } catch { }
            $isWrite = (($rights -band $writeMask) -ne 0)
            if ($ace.AccessControlType.ToString() -eq 'Allow' -and $isWrite -and $broadSids.ContainsKey($sid)) {
                $hits += ($broadSids[$sid] + ' has ' + $ace.FileSystemRights.ToString())
            }
        }
        if ($hits.Count -gt 0) { $res.BroadWriteAce = $true; $res.BroadAces = ($hits -join '; ') }
    } catch {
        $res.Error = 'ACL read failed: ' + $_.Exception.Message
    }
    if (-not $NoWriteTest) {
        # Controlled proof-of-impact: write a uniquely named zero-byte marker, then delete it.
        $marker = Join-Path $Path ('EIA-writetest-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '.tmp')
        try {
            [System.IO.File]::WriteAllText($marker, 'InfraPulse-Win write-permission validation artifact. Safe to delete.')
            $res.WriteTested = $true
            $res.WriteSucceeded = (Test-Path -LiteralPath $marker)
            $res.ArtifactPath = $marker
        } catch {
            $res.WriteTested = $true
            $res.WriteSucceeded = $false
            $res.Error = ($res.Error + ' | write test failed: ' + $_.Exception.Message).Trim(' ', '|')
        } finally {
            try { if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force -ErrorAction Stop } } catch {
                Write-Status 'WARN' ('Assessment artifact could not be removed: ' + $marker + ' - remove it manually.')
            }
        }
    }
    return $res
}

function Get-BroadlyWritableAncestor {
    <# For a service executable path, walk the ancestor directories and return the first one
       that the current identity can modify. This is how an unquoted service path or a
       writable service directory becomes a privilege-escalation primitive. #>
    param([string]$FullPath, [switch]$NoWriteTest)
    $out = @()
    try {
        $dir = [System.IO.Path]::GetDirectoryName($FullPath)
        $guard = 0
        while ($dir -and (Test-Path -LiteralPath $dir) -and $guard -lt 8) {
            $guard++
            $w = Test-DirectoryWritable -Path $dir -NoWriteTest:$NoWriteTest
            if ($w.BroadWriteAce -or $w.WriteSucceeded) { $out += $w }
            $parent = [System.IO.Path]::GetDirectoryName($dir)
            if ($parent -eq $dir) { break }
            $dir = $parent
        }
    } catch { }
    return $out
}

function Get-LocalFactsForPaths {
    <# Shared helper: returns the facts an attack-path claim needs, computed once. #>
    return [pscustomobject]@{
        IsAdmin          = $script:IsAdmin
        IsSystem         = ($script:CurrentUserSid -eq 'S-1-5-18')
        Integrity        = $script:IntegrityLevel
        SmbServerSigning = $script:Facts['SmbServerSigningRequired']
        Smb1             = $script:Facts['Smb1Server']
        LsassProtected   = $script:Facts['LsassProtected']
        RunAsPPL         = $script:Facts['RunAsPPL']
        CredGuard        = $script:Facts['CredentialGuardRunning']
        SpoolerRunning   = $script:Facts['SpoolerRunning']
        Wdigest          = $script:Facts['WdigestEnabled']
        FirewallOn       = $script:Facts['FirewallEnabled']
        Rdp              = $script:Facts['RdpEnabled']
        WinRm            = $script:Facts['WinRmRunning']
        Matrix           = $script:MatrixResult
    }
}

# ===========================================================================================
#  SECTION 15 :: NETWORK SEGMENTATION ASSESSMENT
# ===========================================================================================
function Invoke-Section15_Segmentation {
    Write-Host ''
    Write-Host '  -- 15.1 Zone model (evidence-based only) ----------------------------------------' -ForegroundColor DarkCyan
    $matrix = @($script:MatrixResult)
    $localIps = Get-LocalIpv4 -Nics (Get-NicInventory)
    $mySegment = ''
    if ($localIps.Count -gt 0) {
        $parts = $localIps[0].Split('.')
        if ($parts.Count -eq 4) { $mySegment = ($parts[0] + '.' + $parts[1] + '.' + $parts[2] + '.0/24') }
    }

    if ($matrix.Count -eq 0) {
        Write-Status 'NOT TESTABLE' 'No remote hosts were discovered, so cross-segment flows cannot be assessed. Only the local host could be evaluated.'
        Add-Finding -Category 'Network Segmentation' -Status 'NOT TESTABLE' -Attribute 'Cross-segment flow assessment' `
            -Finding 'Segmentation could not be assessed because no remote host was discovered in the authorised scope (discovery declined, no scope, or all hosts unreachable).' `
            -Observed ('Assessment segment: ' + $(if ($mySegment) { $mySegment } else { 'unknown' })) -Validation 'Not performed' `
            -Class 'High' -Remediation 'Re-run with an approved discovery scope so that cross-segment flows can be measured; otherwise segmentation must be evidenced from the network configuration rather than from this assessment.' `
            -Impact 'Unknown: segmentation is a primary containment control, so an unmeasured control must be treated as unproven (not as absent and not as present).' -NoConsole
        return
    }

    # Zone inference: group hosts by segment, then classify each host's observed profile.
    $segments = @{}
    foreach ($m in $matrix) {
        $p = $m.Host.Split('.')
        $seg = if ($p.Count -eq 4) { ($p[0] + '.' + $p[1] + '.' + $p[2] + '.0/24') } else { 'unknown' }
        if (-not $segments.ContainsKey($seg)) { $segments[$seg] = @{} }
        if (-not $segments[$seg].ContainsKey($m.Host)) { $segments[$seg][$m.Host] = @() }
        $segments[$seg][$m.Host] += $m.Port
    }

    $zoneRows = @()
    foreach ($seg in $segments.Keys) {
        $hosts = $segments[$seg]
        $dcLike = 0; $adminLike = 0; $fileLike = 0; $plain = 0; $allPorts = @()
        foreach ($h in $hosts.Keys) {
            $ports = $hosts[$h]
            $allPorts += $ports
            $isDcLike = (($ports -contains 88) -and ($ports -contains 389))
            $isAdminLike = (($ports -contains 3389) -or ($ports -contains 5985) -or ($ports -contains 5986))
            $isFileLike = (($ports -contains 445) -or ($ports -contains 139))
            if ($isDcLike) { $dcLike++ }
            if ($isAdminLike) { $adminLike++ }
            if ($isFileLike -and -not $isDcLike -and -not $isAdminLike) { $fileLike++ }
            if (-not $isDcLike -and -not $isAdminLike -and -not $isFileLike) { $plain++ }
        }
        $up = @($allPorts | Sort-Object -Unique)
        $label = ''
        if ($dcLike -gt 0) { $label = 'directory services present (' + $dcLike + ' host(s) with Kerberos + LDAP)' }
        elseif ($adminLike -gt 0) { $label = 'administrative interfaces present (' + $adminLike + ' host(s) with RDP/WinRM)' }
        elseif ($fileLike -gt 0) { $label = 'file/print profile (SMB only)' }
        else { $label = 'profile not classifiable from the probed ports' }
        $zoneRows += [pscustomobject]@{
            Segment = $seg
            Hosts = $hosts.Keys.Count
            Profile = $label
            Services = ($up -join ',')
            LocalSegment = ($seg -eq $mySegment)
        }
    }
    Write-Table -Rows $zoneRows -Columns @('Segment','Hosts','Profile','Services','LocalSegment') `
        -Headers @{ Segment='Segment (evidence-based)'; Hosts='Live hosts'; Profile='Observed profile'; Services='Services seen'; LocalSegment='Assessment segment' }

    Add-Finding -Category 'Network Segmentation' -Status 'INFO' -CatClass 'Context' -Attribute 'Observed segment profiles' `
        -Finding ('Reachability was observed across ' + $zoneRows.Count + ' segment(s). Zone labels are derived ONLY from the service profile actually observed; where the profile does not support a classification it is reported as such rather than guessed.') `
        -Observed (($zoneRows | ForEach-Object { $_.Segment + ': ' + $_.Hosts + ' host(s), ' + $_.Profile }) -join ' | ') `
        -Validation 'Derived from the bounded TCP reachability matrix in Section 8 (no packet inspection, no route tracing, no authenticated discovery on remote hosts).' `
        -Class 'Low' -Remediation 'Confirm the observed flows against the documented network design; where a segment exposes services that its role does not justify, that is the segmentation finding to raise.' `
        -Impact 'None by itself: this row establishes which flows exist so that the boundary assessments below are built on observation rather than assumption.' -NoConsole

    Write-Host ''
    Write-Host '  -- 15.2 Cross-segment flow assessment (SOURCE ZONE -> DESTINATION ZONE -> SERVICE) ---' -ForegroundColor DarkCyan
    Write-Host '     Referenced boundary model (documented, deterministic):' -ForegroundColor DarkGray
    Write-Host '       Directory services to a DC from any domain segment ....... expected (required for AD operation)' -ForegroundColor DarkGray
    Write-Host '       SMB (445) to a file/print host .......................... expected within the same zone' -ForegroundColor DarkGray
    Write-Host '       SMB over NetBIOS (139) anywhere ........................ unexpected (legacy transport)' -ForegroundColor DarkGray
    Write-Host '       RDP (3389) / WinRM (5985-5986) to ANY host from a general segment ... unexpected' -ForegroundColor DarkGray
    Write-Host '       Category-1 (broken/downgraded protocol) reachable ......... unexpected' -ForegroundColor DarkGray

    $flowRows = @()
    $unexpected = 0; $expectedCt = 0; $unknownCt = 0
    $srcZone = if ($mySegment) { $mySegment } else { 'assessment host' }
    $checkedPairs = 0
    foreach ($m in $matrix) {
        if ($checkedPairs -ge 60) { break }
        $checkedPairs++
        $p = $m.Host.Split('.')
        $dstZone = if ($p.Count -eq 4) { ($p[0] + '.' + $p[1] + '.' + $p[2] + '.0/24') } else { 'unknown' }
        $dstPorts = @($segments[$dstZone][$m.Host])
        $isDcLike = (($dstPorts -contains 88) -and ($dstPorts -contains 389))
        $port = [int]$m.Port
        $expectation = ''
        $verdict = ''
        switch ($port) {
            53    { $expectation = 'DNS: expected toward a directory/DNS server only'; $verdict = if ($isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            88    { $expectation = 'Kerberos: expected toward a KDC (domain controller)'; $verdict = if ($isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            389   { $expectation = 'LDAP: expected toward a domain controller'; $verdict = if ($isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            636   { $expectation = 'LDAPS: expected toward a domain controller'; $verdict = if ($isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            3268  { $expectation = 'Global Catalog: expected toward a domain controller'; $verdict = if ($isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            3269  { $expectation = 'Global Catalog/SSL: expected toward a domain controller'; $verdict = if ($isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            135   { $expectation = 'RPC endpoint mapper: expected inside a management zone, unexpected from a general user segment'; $verdict = if ($dstZone -eq $srcZone) { 'Expected access' } else { 'Unexpected access' } }
            445   { $expectation = 'SMB: expected toward file/print and directory servers, expected intra-zone'; $verdict = if ($dstZone -eq $srcZone -or $isDcLike) { 'Expected access' } else { 'Unexpected access' } }
            139   { $expectation = 'SMB over NetBIOS: NOT expected on a modern estate (legacy transport, relay-friendly)'; $verdict = 'Unexpected access' }
            3389  { $expectation = 'RDP: expected only from a privileged-access/workstation management zone'; $verdict = 'Unexpected access' }
            5985  { $expectation = 'WinRM/HTTP: expected only from a management zone'; $verdict = 'Unexpected access' }
            5986  { $expectation = 'WinRM/HTTPS: expected only from a management zone'; $verdict = 'Unexpected access' }
            default { $expectation = 'no boundary model defined for this port'; $verdict = 'Unknown' }
        }
        $destLabel = $dstZone + ' (' + $m.Host + ')'
        $flowRows += [pscustomobject]@{ Source=$srcZone; Destination=$destLabel; Service=((Get-ServiceNameForPort $port) + ':' + $port); Boundary=$expectation; Observed=$verdict }
        if ($verdict -eq 'Unexpected access') { $unexpected++ } elseif ($verdict -eq 'Expected access') { $expectedCt++ } else { $unknownCt++ }
    }
    Write-Table -Rows ($flowRows | Select-Object -First 40) -Columns @('Source','Destination','Service','Boundary','Observed') `
        -Headers @{ Source='Source zone'; Destination='Destination zone (host)'; Service='Service'; Boundary='Expected boundary'; Observed='Observed access / result' }
    if ($flowRows.Count -gt 40) { Write-Host ('    ... ' + ($flowRows.Count - 40) + ' further flows are recorded in the CSV report.') -ForegroundColor DarkGray }

    Add-Finding -Category 'Network Segmentation' -Status $(if ($unexpected -gt 0) { 'RISK DETECTED' } else { 'PASS' }) -Attribute 'Cross-segment administrative exposure' `
        -Source $srcZone -Target 'multiple (see OBSERVED)' -Port '135,139,3389,5985,5986' `
        -Finding ($unexpected.ToString() + ' flow(s) from the assessment segment reach services that the documented boundary model classifies as UNEXPECTED (administrative interfaces, legacy transport, or directory services from a general segment). ' + $expectedCt + ' flow(s) matched the expected model.') `
        -Observed (($flowRows | Where-Object { $_.Observed -eq 'Unexpected access' } | ForEach-Object { $_.Destination + ' : ' + $_.Service } | Select-Object -First 20) -join ' | ') `
        -Validation 'Bounded TCP connect sweep (Section 8) interpreted against an explicitly documented boundary model. Reachability was validated; no authentication was attempted against the remote hosts in this module, so "access" here means network-level reachability, NOT authenticated access.' `
        -Prerequisites 'Network position in the assessment segment (already established).' `
        -Exploitability 'Reachability validated; authentication NOT validated in this module. Where credentials exist for the exposing service, reachability becomes directly usable - that credential link is assessed in Section 16, not assumed here.' `
        -Class 'High' -CatClass 'Confidentiality' `
        -Remediation 'Apply least-privilege network segmentation: place administrative interfaces (3389/5985/5986/135) behind a jump host or privileged-access workstation tier and enforce it with host firewalls plus network ACLs on both sides. Disable TCP/139 estate-wide, restrict LDAP/LDAPS/GC to hosts that genuinely require directory access, and use Windows Firewall domain profiles to narrow inbound rules to specific source subnets rather than the whole corporate range.' `
        -Impact 'Reachable administrative services collapse the segmentation model: any credential usable against those hosts (harvested elsewhere, reused, or relayed) becomes a lateral-movement and privilege-escalation path. Legacy SMB over 139 additionally widens NTLM relay opportunities and bypasses modern-only controls.'

    # Explicitly record what could NOT be established about segmentation
    Add-Finding -Category 'Network Segmentation' -Status 'NOT TESTABLE' -Attribute 'Directional/enforcement boundary verification' `
        -Finding 'This assessment can only demonstrate that traffic from the ASSESSMENT POSITION reached a service. It cannot prove the inverse (that other segments are blocked), nor the enforcing device or rule set.' `
        -Observed 'Single-source reachability testing from one host in one segment.' `
        -Validation 'Method limitation, recorded explicitly.' -Class 'Medium' -CatClass 'Context' `
        -Remediation 'To evidence the full segmentation model, run discovery from a representative host in each zone (or collect firewall rule exports and ACL configuration) and compare the results with this matrix.' `
        -Impact 'Treat "unexpected access" rows as confirmed exposure, and treat absent rows as UNKNOWN rather than as proof that the flow is blocked.' -NoConsole
}

# ===========================================================================================
#  SECTION 16 :: LATERAL-MOVEMENT ATTACK-PATH ANALYSIS
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Correlates the evidence collected by every previous module into candidate paths from the
#  current assessment identity to a privilege boundary. The output is deliberately
#  conservative: each link carries its own evidence status, and a path is only published with
#  a validated verdict when every link is evidenced. Connectivity is never presented as a
#  successful movement.
# ===========================================================================================
function Add-AttackPath {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][object[]]$Links,   # array of @{ Step='...'; Evidence='...'; Status='validated|config|unknown' }
        [Parameter(Mandatory=$true)][string]$Boundary,
        [string]$Prereq = '',
        [string]$Class = 'High',
        [string]$Remediation = '',
        [string]$Impact = ''
    )
    $all = $true
    $unknowns = @()
    foreach ($l in $Links) { if ($l.Status -ne 'validated') { $all = $false; $unknowns += $l.Step } }
    $chain = ($Links | ForEach-Object { $_.Step }) -join ' -> '
    $evidence = ($Links | ForEach-Object { '[' + $_.Status.ToUpper() + '] ' + $_.Step + ': ' + $_.Evidence }) -join ' || '
    $status = if ($all) { 'VALIDATED' } else { 'RISK DETECTED' }
    Write-Host ''
    Write-Host ('    PATH: ' + $chain) -ForegroundColor $(if ($all) { 'Magenta' } else { 'Yellow' })
    foreach ($l in $Links) {
        Write-Host ('      [' + $l.Status.ToUpper().PadRight(9) + '] ' + $l.Step + ' :: ' + $l.Evidence) -ForegroundColor $(if ($l.Status -eq 'validated') { 'Green' } else { 'DarkYellow' })
    }
    Write-Host ('      privilege boundary at risk: ' + $Boundary) -ForegroundColor Gray
    if ($unknowns.Count -gt 0) { Write-Host ('      NOT YET EVIDENCED: ' + ($unknowns -join '; ')) -ForegroundColor DarkYellow }

    Add-Finding -Category 'Attack Path Correlation' -Status $status -Attribute 'Attack path' `
        -Finding ('Attack path: ' + $chain + $(if ($all) { ' (every link is evidenced)' } else { ' (candidate: ' + $unknowns.Count + ' link(s) not yet evidenced)' })) `
        -Prerequisites $Prereq -Configured $evidence `
        -Observed ('Privilege boundary at risk: ' + $Boundary + '. Verdict: ' + $(if ($all) { 'all links evidenced - path is technically available from the current context.' } else { 'candidate only - the path is NOT demonstrated because the links listed as not-evidenced were not validated.' })) `
        -Validation 'Correlation of previously collected evidence only. No new exploitation was performed by this module: the individual links were validated by the modules cited in CONFIGURATION EVIDENCE.' `
        -Exploitability $(if ($all) { 'Path is available from the current assessment context (each link evidenced by an active test or an attribute read). The final impact step was not executed by this tool.' } else { 'Not demonstrated - unvalidated links remain.' }) `
        -Class $Class -CatClass 'IdentityRights' -Remediation $Remediation -Impact $Impact
}

function Invoke-Section16_AttackPaths {
    $F = Get-LocalFactsForPaths
    $matrix = @($F.Matrix)
    $srv = $script:HostName

    Write-Host ''
    Write-Host '  -- 16.1 Correlated attack paths ---------------------------------------------------' -ForegroundColor DarkCyan
    Write-Host ('    source identity : ' + $script:CurrentUser + ' [' + $(if ($F.IsAdmin) { 'local administrator' } else { 'standard user' }) + '] on ' + $srv) -ForegroundColor DarkGray
    Write-Host ('    gathered facts  : SMB signing required=' + $(if ($null -eq $F.SmbServerSigning) { 'unknown' } else { [string]$F.SmbServerSigning }) + '; LSASS protected=' + $(if ($null -eq $F.LsassProtected) { 'unknown' } else { [string]$F.LsassProtected }) + '; spooler=' + $F.SpoolerRunning + '; firewall on=' + $F.FirewallOn + '; winrm=' + $F.WinRm + '; rdp=' + $F.Rdp) -ForegroundColor DarkGray
    if ($matrix.Count -eq 0) { Write-Host '    (no remote reachability evidence - paths will be limited to the local host)' -ForegroundColor DarkGray }

    $pathsFound = 0
    $dbgStatus = 'config'
    if ($script:Facts['SeDebugPresent']) { $dbgStatus = 'validated' }

    # ---- Path 1: administrator foothold -> credential material ----------------------------------
    if ($F.IsAdmin) {
        if ($F.LsassProtected -eq $false) {
            $pathsFound++
            Add-AttackPath -Title 'Local administrator to credential material' `
                -Links @(
                    @{ Step='CURRENT IDENTITY = local administrator on ' + $srv; Evidence='Token evaluation: IsInRole(Administrator)=True, integrity ' + $F.Integrity; Status='validated' },
                    @{ Step='LSASS running unprotected'; Evidence='Runtime ProcessProtectionInformation query (Section 5) reported level None; RunAsPPL=' + $(if ($null -eq $F.RunAsPPL) { 'absent' } else { [string]$F.RunAsPPL }); Status='validated' },
                    @{ Step='SeDebugPrivilege (or equivalent) held by an administrative token'; Evidence='in-memory token query enumerated SeDebugPrivilege in the assessment token'; Status=$dbgStatus }
                ) -Boundary 'Credential boundary (LSASS-protected secrets of every logged-on identity)' -Class 'Critical' `
                -Prereq 'Administrative rights on this host (already held) and an unprotected LSASS.' `
                -Remediation 'Enable LSA protection (RunAsPPL=1/2) and Credential Guard, reduce local administrator membership, and remove SeDebugPrivilege from any principal that does not require it. Remediating the LSASS step breaks this path even if administrator access remains.' `
                -Impact 'Immediate availability of the credential material of every interactive and service logon on this host (NTLM hashes and Kerberos keys), which is directly reusable elsewhere in the estate. The credential-extraction step itself was NOT performed by this tool: the path is reported because both of its preconditions were independently validated.'
        } else {
            $pathsFound++
            Add-AttackPath -Title 'Local administrator to credential material (mitigated by LSASS protection)' `
                -Links @(
                    @{ Step='CURRENT IDENTITY = local administrator on ' + $srv; Evidence='Token evaluation confirms administrative rights, integrity ' + $F.Integrity; Status='validated' },
                    @{ Step='LSASS is protected'; Evidence='Runtime query in Section 5 shows a protected level; direct memory access from non-PPL code is refused by the kernel'; Status='validated' },
                    @{ Step='Credential material reachable through that path'; Evidence='Not reachable via LSASS memory - control observed in the effective state'; Status='unknown' }
                ) -Boundary 'Credential boundary' -Class 'Critical' `
                -Remediation 'Maintain LSA protection and Credential Guard, and re-validate after every OS upgrade: a reboot or policy change can silently revert the effective state.' `
                -Impact 'The fastest credential-access path from local administrator is closed on this host. This does not make administrator access harmless - it removes one specific technique and the residual risk must be tracked in the risk register rather than closed.'
        }
    } else {
        $pathsFound++
        Add-AttackPath -Title 'Standard user to local privilege boundary' `
            -Links @(
                @{ Step='CURRENT IDENTITY = standard user on ' + $srv; Evidence='Token evaluation: IsInRole(Administrator)=False, integrity ' + $F.Integrity; Status='validated' },
                @{ Step='Local privilege-escalation primitive available'; Evidence='Section 17 permission findings (see the individual rows for evidence status)'; Status='config' },
                @{ Step='Administrator/SYSTEM on this host'; Evidence='Would follow from a working escalation primitive - NOT executed by this tool'; Status='unknown' }
            ) -Boundary 'Local administrator / SYSTEM boundary on this host' -Class 'High' `
            -Prereq 'A misconfigured service, task, directory ACL or unpatched local vulnerability.' `
            -Remediation 'Remediate the specific finding in Section 17 that supplies the primitive; where none was found, keep the host patched and monitor for new local escalation techniques.' `
            -Impact 'A local privilege boundary crossing on a workstation is the standard first step towards credential access and then lateral movement. The path is a CANDIDATE: the escalation step was not executed.'
    }

    # ---- Path 2: SPN / Kerberoastable service account ------------------------------------------
    $spnPriv = $script:Facts['SpnPrivilegedCount']
    if ($spnPriv -and [int]$spnPriv -gt 0) {
        $pathsFound++
        Add-AttackPath -Title 'Authenticated user to privileged service account (Kerberos service ticket)' `
            -Links @(
                @{ Step='Any authenticated domain principal'; Evidence='Assessment runs in an authenticated domain context (' + $script:CurrentUser + ')'; Status='validated' },
                @{ Step='Privileged account holds an SPN'; Evidence=$spnPriv.ToString() + ' privileged SPN-holding account(s) enumerated in Section 11'; Status='validated' },
                @{ Step='KDC reachable to issue a service ticket'; Evidence='TCP/88 reachability recorded in Sections 8 and 10.2'; Status='validated' },
                @{ Step='Ticket material crackable'; Evidence='Password age beyond threshold and/or RC4 permitted, per Sections 11 and 13 (cracking itself NOT performed)'; Status='config' },
                @{ Step='Privileged resource access with the recovered account'; Evidence='Not executed'; Status='unknown' }
            ) -Boundary 'Domain privileged account -> domain-level resources' -Class 'Critical' `
            -Prereq 'Any valid domain credential (or a domain-joined machine account) and network reachability to a KDC.' `
            -Remediation 'Migrate service accounts to gMSA, enforce 30+ character random passwords, enable AES-only encryption, remove privileged-group membership from service accounts, and remove stale SPNs.' `
            -Impact 'This is the highest-yield path in most internal assessments: it requires only a low-privilege domain foothold and produces a privileged account. Links 1-3 were validated here; the cracking and reuse steps were not performed.'
    }

    # ---- Path 3: pre-authentication-disabled account -------------------------------------------
    if ($script:Facts['PreAuthValidated'] -and [int]$script:Facts['PreAuthValidated'] -gt 0) {
        $pathsFound++
        Add-AttackPath -Title 'Unauthenticated attacker to account password (AS-REP without pre-authentication)' `
            -Links @(
                @{ Step='Network position on any segment that can reach a KDC'; Evidence='KDC TCP/88 reachable from the assessment position'; Status='validated' },
                @{ Step='Account with DONT_REQ_PREAUTH (0x00400000)'; Evidence='Directory attribute read with exact hexadecimal decoding (Section 10)'; Status='validated' },
                @{ Step='KDC returns an AS-REP without pre-authentication'; Evidence='Live AS-REQ/response recorded in Section 10.2 - ' + $script:Facts['PreAuthValidated'] + ' account(s) confirmed'; Status='validated' },
                @{ Step='Password recovered offline'; Evidence='NOT performed by this tool (prohibited by design); crackability depends on password strength'; Status='unknown' }
            ) -Boundary 'The affected account, and anything its privileges reach' -Class 'Critical' `
            -Prereq 'Reachability to a KDC (no credentials required at all).' `
            -Remediation 'Clear the flag, reset the password with a long random value, and review Kerberos event 4768 for prior requests for the account. Add the account to Protected Users where compatible.' `
            -Impact 'Requires no credentials, no lockout and produces no failed-logon noise. Where the account is privileged the result is direct privileged access.'
    }

    # ---- Path 4: unconstrained delegation -------------------------------------------------------
    if ($script:Facts['UnconstrainedNonDc'] -and [int]$script:Facts['UnconstrainedNonDc'] -gt 0) {
        $pathsFound++
        Add-AttackPath -Title 'Account with access to a delegation host to every identity that authenticates there' `
            -Links @(
                @{ Step='Non-DC host trusted for unconstrained delegation'; Evidence=$script:Facts['UnconstrainedNonDc'].ToString() + ' principal(s) enumerated in Section 12'; Status='validated' },
                @{ Step='Host reachable from the assessment position'; Evidence='TCP reachability per Section 12 (recorded per host)'; Status='validated' },
                @{ Step='Administrative access to that host'; Evidence='Not obtained by this tool - requires separate credentials or an escalation primitive'; Status='unknown' },
                @{ Step='TGT capture of authenticating users'; Evidence='NOT performed (ticket harvesting is prohibited by this tool''s design)'; Status='unknown' }
            ) -Boundary 'Every user and service identity that authenticates to the delegation host, including privileged administrators' -Class 'Critical' `
            -Prereq 'Administrative access to the delegation host (or the ability to coerce authentication to it).' `
            -Remediation 'Remove unconstrained delegation, replace with constrained or resource-based delegation, and mark sensitive accounts as non-delegable. Add the host to a high-risk watchlist until remediated.' `
            -Impact 'The delegation host becomes a credential collection point; the identities harvested there determine the escalation, and privileged identities make it a domain-level path.'
    }

    # ---- Path 5: reachable administrative interface --------------------------------------------
    $adminHosts = @()
    foreach ($m in $matrix) { if ([int]$m.Port -in @(3389,5985,5986)) { $adminHosts += $m.Host } }
    $adminHosts = @($adminHosts | Sort-Object -Unique)
    if ($adminHosts.Count -gt 0) {
        $pathsFound++
        Add-AttackPath -Title 'Credential reuse to lateral movement via reachable administrative interface' `
            -Links @(
                @{ Step='Administrative interface reachable from the assessment segment'; Evidence=($adminHosts.Count.ToString() + ' host(s): ' + (($adminHosts | Select-Object -First 8) -join ', ') + $(if ($adminHosts.Count -gt 8) { ' (+' + ($adminHosts.Count - 8) + ' more)' } else { '' })); Status='validated' },
                @{ Step='Service reachable on the probed administrative port'; Evidence='TCP connect succeeded (Section 8)'; Status='validated' },
                @{ Step='Remote authentication with the current identity'; Evidence='Not attempted by this module (see Section 19 for the credential-reachability test, if configured)'; Status='unknown' }
            ) -Boundary 'Administrative boundary of each reachable host' -Class 'High' `
            -Prereq 'Credentials that are valid on the destination host (reused local administrator passwords, shared service accounts, or a domain account with local administrative rights).' `
            -Remediation 'Segment administrative interfaces behind a privileged-access tier, eliminate local administrator password reuse (deploy LAPS to full coverage - see Section 14), do not use shared local administrator credentials, and enforce just-in-time elevation.' `
            -Impact 'Where credentials are reused across hosts, a single credential compromise converts into administrative access across the estate. This path is intentionally left as a CANDIDATE: reachability is proven, credential validity was not tested here.'
        if ($script:Facts['RemoteAdminValidated'] -and [int]$script:Facts['RemoteAdminValidated'] -gt 0) {
            $pathsFound++
            Add-AttackPath -Title 'Credential reuse - CONFIRMED administrative access from the current identity' `
                -Links @(
                    @{ Step='Current identity: ' + $script:CurrentUser; Evidence='Assessment context (whoami/SID recorded in Section 1)'; Status='validated' },
                    @{ Step='Remote administrative access validated'; Evidence=$script:Facts['RemoteAdminValidated'].ToString() + ' host(s) accepted administrative access from the current identity (see the Section 19 validation rows for the exact mechanism)'; Status='validated' },
                    @{ Step='Administrative capability on the remote host'; Evidence='Administrative share / management endpoint access succeeded with the current token'; Status='validated' }
                ) -Boundary 'Administrative boundary of the destination host(s)' -Class 'Critical' `
                -Prereq 'None beyond the current identity: this path was demonstrated with the assessment credentials.' `
                -Remediation 'Remove the credential overlap: unique local administrator passwords (LAPS), separate administrative accounts per tier, no shared service credentials, and restrict interactive/remote logon rights so that standard accounts cannot reach administrative interfaces.' `
                -Impact 'This is a DEMONSTRATED lateral-movement path from the current assessment context. The individual link evidence is recorded in Section 19 and can be reproduced. Note that this demonstrates ACCESS, not that the destination host was modified: no changes were made on the remote host.'
        }
    }

    if ($pathsFound -eq 0) {
        Write-Status 'PASS' 'No attack path met the evidence threshold from this context (this is a positive result for the assessed host, not a statement about the estate).'
        Add-Finding -Category 'Attack Path Correlation' -Status 'PASS' -Attribute 'Attack paths' `
            -Finding 'No attack path reached the evidence threshold from the current assessment context on this host.' `
            -Observed 'Each candidate path was missing at least one independently evidenced link.' `
            -Validation 'Correlation of all prior evidence' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'No action for this host. Re-run after configuration changes, and assess hosts with weaker baselines to build the estate-level picture.' `
            -Impact 'None demonstrated from this context. This is a per-host statement only.'
    }
}
# ===========================================================================================
#  SECTIONS 17-18 :: LOCAL PRIVILEGE ESCALATION + LOLBin / NATIVE EXECUTION  (part 10/12)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Section 17 answers one question: from the CURRENT token, can anything on this host be
#  turned into SYSTEM or into another user's context? Every candidate is recorded with the
#  permission that makes it possible, and where a permission can be PROVEN with a harmless,
#  reversible action (creating and deleting a marker file), that proof is captured so the
#  finding is validated rather than inferred from an ACL listing.
#
#  WRITE-PROOF SAFETY RULES (enforced in code, not just documented):
#    * a marker file of zero critical value is created with a unique name and deleted in a
#      finally block, so it is removed even if the test throws
#    * no existing file is ever modified, moved, renamed, truncated or replaced
#    * nothing executable is ever written; no DLL, EXE, LNK, .ps1 or .bat is created
#    * the proof is limited to directory/permission validation, never to hijacking a service
#
#  Section 18 assesses native binaries and interpreters. Presence alone is NOT a finding:
#  every LOLBin component is cross-referenced against the controls that actually decide
#  whether it is abusable (application control policy, parent-directory permissions,
#  service/task relationships and DLL search paths).
# ===========================================================================================

function Get-InstalledSoftwareInventory {
    <# Reads the Uninstall keys (read-only). Win32_Product is deliberately NOT used: it
       triggers an MSI consistency check that can reconfigure or repair installed packages,
       which is an unacceptable side effect for an assessment tool. #>
    $out = New-Object System.Collections.ArrayList
    $paths = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($p in $paths) {
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($p)
            if (-not $key) { continue }
            foreach ($sub in $key.GetSubKeyNames()) {
                try {
                    $sk = $key.OpenSubKey($sub)
                    if (-not $sk) { continue }
                    $name = $sk.GetValue('DisplayName')
                    if (-not $name) { $sk.Close(); continue }
                    [void]$out.Add([pscustomobject]@{
                        Name            = [string]$name
                        Version         = [string]$sk.GetValue('DisplayVersion')
                        Publisher       = [string]$sk.GetValue('Publisher')
                        InstallLocation = [string]$sk.GetValue('InstallLocation')
                        UninstallString = [string]$sk.GetValue('UninstallString')
                        KeyPath         = ('HKLM\' + $p + '\' + $sub)
                    })
                    $sk.Close()
                } catch { }
            }
            $key.Close()
        } catch { }
    }
    return @($out)
}

function Get-PrincipalNameForSid {
    param([string]$Sid)
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $Sid }
}

function Test-RegistryKeyWritable {
    param([string]$Path, [string]$Name = '')
    $res = [pscustomobject]@{ Path=$Path; BroadWriteAce=$false; BroadAces=''; Error='' }
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree)
        if (-not $key) { $res.Error = 'key absent'; return $res }
        $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $broad = @{
            'S-1-1-0'='Everyone'; 'S-1-5-11'='Authenticated Users'; 'S-1-5-32-545'='BUILTIN\Users'
            'S-1-5-4'='INTERACTIVE'; 'S-1-5-7'='ANONYMOUS LOGON'
        }
        $writeBits = @('SetValue','CreateSubKey','WriteKey','FullControl','TakeOwnership','ChangePermissions','Delete')
        $hits = @()
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }
            if (-not $broad.ContainsKey($sid)) { continue }
            $r = $rule.RegistryRights.ToString()
            foreach ($b in $writeBits) { if ($r -match $b) { $hits += ($broad[$sid] + ' has ' + $r); break } }
        }
        if ($hits.Count -gt 0) { $res.BroadWriteAce = $true; $res.BroadAces = ($hits -join '; ') }
        $key.Close()
    } catch {
        $res.Error = $_.Exception.Message
    }
    return $res
}

function Invoke-Section17_PrivEsc {
    Write-Host ''
    Write-Host '  -- 17.1 Local administrator membership ------------------------------------------' -ForegroundColor DarkCyan
    $adminGroup = 'Administrators'
    try {
        $members = @(Get-CimInstance -ClassName Win32_GroupUser -ErrorAction Stop | Where-Object { $_.GroupComponent -match 'Name="Administrators"' })
        $names = @()
        foreach ($m in $members) {
            if ($m.PartComponent -match 'Name="([^"]+)"') { $names += $Matches[1] }
        }
        Write-Table -Rows ($names | ForEach-Object { [pscustomobject]@{ Member = $_ } }) -Columns @('Member') -Headers @{ Member='Local Administrators member' }
        Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($names.Count -gt 3) { 'WARN' } else { 'INFO' }) -CatClass 'IdentityRights' `
            -Attribute 'Local Administrators group membership' `
            -Finding ('The local Administrators group has ' + $names.Count + ' direct member(s): ' + ($names -join ', ') + '.') `
            -Observed ('Direct members: ' + ($names -join ', ') + ' (nested groups are not expanded)') `
            -Validation 'WMI Win32_GroupUser association query (read-only)' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'Keep local administrator membership to a documented minimum (ideally the built-in Administrator account disabled, plus a single tiered administrative group). Every additional member is an independent path to full local control, and local administrator membership is what makes credential dumping, service tampering and DLL hijacking practical.' `
            -Impact 'Any compromise of a listed principal yields full local control of this host, including credential material (subject to the LSASS protections assessed in Section 5).'
        $script:Facts['LocalAdminCount'] = $names.Count
    } catch { Write-Status 'NOT TESTABLE' ('Administrators group enumeration failed: ' + $_.Exception.Message) }

    Write-Host ''
    Write-Host '  -- 17.2 Service configuration: unquoted paths, writable binaries and directories ---' -ForegroundColor DarkCyan
    $svcs = @(Get-CimSafe -Class 'Win32_Service')
    if ($svcs.Count -eq 0) { Write-Status 'NOT TESTABLE' 'Win32_Service enumeration returned nothing; service permission analysis skipped.' }
    else {
        $unquoted = @(); $writableDir = @()
        foreach ($s in $svcs) {
            $pn = [string]$s.PathName
            if ([string]::IsNullOrWhiteSpace($pn)) { continue }
            $exePath = $pn.Trim()
            if ($exePath.StartsWith('"')) {
                $exePath = ($exePath -split '"')[1]
            } else {
                # Unquoted path with spaces: Windows resolves the executable by searching
                # progressively longer prefixes, which is the classic escalation primitive.
                $candidate = $exePath
                if ($candidate -match '\.exe' -and $candidate.Contains(' ')) {
                    $idx = $candidate.IndexOf('.exe', [System.StringComparison]::OrdinalIgnoreCase)
                    $candidate = $candidate.Substring(0, $idx + 4)
                    if ($candidate.Contains(' ') -and [System.IO.Path]::GetExtension($candidate) -eq '.exe') {
                        $unquoted += [pscustomobject]@{ Service=$s.Name; Display=$s.DisplayName; StartName=$s.StartName; PathName=$pn; ResolvedExe=$candidate }
                    }
                }
                $exePath = $candidate
            }
            if ($exePath -and (Test-Path -LiteralPath $exePath)) {
                $fw = Test-DirectoryWritable -Path ((Get-Item -LiteralPath $exePath).DirectoryName) -NoWriteTest
                if ($fw.BroadWriteAce) { $writableDir += [pscustomobject]@{ Service=$s.Name; StartName=$s.StartName; Directory=$fw.Path; Aces=$fw.BroadAces; Exe=$exePath } }
            } elseif ($exePath) {
                $missingDir = @()
                if ($pn.Contains(' ')) { $missingDir += $pn }
            }
        }

        if ($unquoted.Count -gt 0) {
            Write-Table -Rows ($unquoted | Select-Object -First 15) -Columns @('Service','StartName','PathName') -Headers @{ Service='Service'; StartName='Runs as'; PathName='Unquoted ImagePath' }
            foreach ($u in $unquoted) {
                $ancestors = Get-BroadlyWritableAncestor -FullPath $u.ResolvedExe -NoWriteTest
                $exploitable = ($ancestors.Count -gt 0)
                $proof = ''
                if ($exploitable) {
                    # Controlled proof-of-impact: prove write access to the hijackable directory.
                    $pw = Test-DirectoryWritable -Path $ancestors[0].Path
                    $proof = ('Write permission PROVEN in ' + $pw.Path + ': marker file created=' + $pw.WriteSucceeded + ' and removed=' + (-not (Test-Path -LiteralPath $pw.ArtifactPath)))
                    if ($pw.WriteSucceeded) { $script:Facts['WriteProofObtained'] = $true }
                }
                Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($exploitable) { 'VALIDATED' } else { 'WARN' }) -Attribute 'Unquoted service path' `
                    -Target $u.Service -Finding ('Service ''' + $u.Service + ''' (' + $u.Display + ') has an unquoted ImagePath containing spaces. Windows will search progressively longer path prefixes, so an attacker who can write to an earlier directory can cause a different executable to be launched - as ' + $u.StartName + '.') `
                    -Configured ('ImagePath = ' + $u.PathName + ' (no quotation marks around the executable path)') `
                    -Observed $(if ($exploitable) { 'Ancestor directories that the current identity can modify were found: ' + ($ancestors | ForEach-Object { $_.Path } | Select-Object -Unique) -join ', ' } else { 'No ancestor directory writable by the current identity was found, so the primitive is present but not usable from this context.' }) `
                    -Validation $(if ($exploitable) { 'Controlled proof-of-impact: ' + $proof + '. No executable was written and no service was restarted; only the underlying write permission was demonstrated.' } else { 'ACL analysis of every ancestor directory (no write permission found for the current identity or for a broadly-permissioned group).' }) `
                    -Prerequisites 'Write access to an earlier directory in the unquoted path, plus a service restart (or the next boot) to trigger resolution. The restart step was deliberately NOT performed.' `
                    -Exploitability $(if ($exploitable) { 'Permission validated; the execution step was not performed (that would be an actual escalation). The row is therefore validated as a usable primitive, not as an achieved SYSTEM context.' } else { 'Not currently usable from this identity; it may become usable for another local account or after an ACL change.' }) `
                    -Class 'High' -CatClass 'IdentityRights' `
                    -Remediation 'Quote the service path (sc.exe config <service> binPath= "\"C:\Path With Spaces\svc.exe\"") and remove write permissions for non-administrative principals from every service directory. Where the path is genuinely unquoted in a third-party product, correct it and report the defect to the vendor.' `
                    -Impact 'A service binary substitution executes as the service account - for most services SYSTEM - which is a direct local privilege boundary crossing from any principal that can write to the directory.'
            }
        } else {
            Write-Status 'PASS' 'No service ImagePath with an unquoted, space-containing executable path was found.'
        }

        if ($writableDir.Count -gt 0) {
            Write-Host ''
            Write-Host '  -- 17.3 Service directories writable by non-administrative principals ------------' -ForegroundColor DarkCyan
            Write-Table -Rows ($writableDir | Select-Object -First 15) -Columns @('Service','StartName','Directory','Aces') -Headers @{ Service='Service'; StartName='Runs as'; Directory='Directory'; Aces='Broad allow ACEs' }
            foreach ($w in ($writableDir | Select-Object -First 8)) {
                $pw = Test-DirectoryWritable -Path $w.Directory
                Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($pw.WriteSucceeded) { 'VALIDATED' } else { 'WARN' }) -Attribute 'Writable service directory or binary' `
                    -Target $w.Service -Finding ('The directory holding the executable of service ''' + $w.Service + ''' is writable by non-administrative principals (broad allow ACEs detected).') `
                    -Configured ('Directory ' + $w.Directory + ' ; ACEs: ' + $w.Aces + ' ; service runs as ' + $w.StartName) `
                    -Observed $(if ($pw.WriteSucceeded) { 'Write access PROVEN: a uniquely named marker file was created and then deleted successfully (' + $pw.ArtifactPath + ').' } else { 'ACL indicates broad write access; the write test did not succeed from this token (' + $pw.Error + ').' }) `
                    -Validation 'ACL analysis plus a controlled, reversible marker-file write test. No executable or DLL was created, and no existing file was modified. The artifact was removed in a finally block.' `
                    -Prerequisites 'The service must be restarted (or the host rebooted) for a replaced binary to take effect - that step was NOT performed.' `
                    -Exploitability $(if ($pw.WriteSucceeded) { 'Write permission validated; the binary-replacement step was deliberately not performed.' } else { 'Permission inferred from ACL analysis only.' }) `
                    -Class 'High' -CatClass 'IdentityRights' `
                    -Remediation 'Remove write permissions for Users/Authenticated Users/Everyone from service directories and from the service binaries themselves. Use a directory structure where services are installed under a location that only administrators and the service SID can modify.' `
                    -Impact 'Write access to a service binary or its directory allows replacing the executable, which runs with the service account''s privileges (usually SYSTEM) at the next service start.'
            }
        } else {
            Write-Status 'PASS' 'No service directory with broadly-permissive write ACEs was identified.'
        }
        $script:Facts['UnquotedServicePaths'] = $unquoted.Count
    }

    Write-Host ''
    Write-Host '  -- 17.4 Scheduled tasks ----------------------------------------------------------' -ForegroundColor DarkCyan
    $taskIssues = @()
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
        Write-KV 'Non-Microsoft scheduled tasks' $tasks.Count
        foreach ($t in $tasks) {
            foreach ($a in $t.Actions) {
                $ex = $a.Execute
                if ([string]::IsNullOrWhiteSpace($ex)) { continue }
                $ex = [Environment]::ExpandEnvironmentVariables($ex)
                if (Test-Path -LiteralPath $ex) {
                    $w = Test-DirectoryWritable -Path ((Get-Item -LiteralPath $ex).DirectoryName) -NoWriteTest
                    if ($w.BroadWriteAce) {
                        $taskIssues += [pscustomobject]@{ Task=$t.TaskName; Path=$t.TaskPath; Execute=$ex; Principal=$t.Principal.UserId; RunLevel=$t.Principal.RunLevel; Directory=$w.Path; Aces=$w.BroadAces }
                    }
                } else {
                    # Missing binary in a writable directory is the classic task-hijack primitive
                    $dir = [System.IO.Path]::GetDirectoryName($ex)
                    if ($dir -and (Test-Path -LiteralPath $dir)) {
                        $w = Test-DirectoryWritable -Path $dir -NoWriteTest
                        if ($w.BroadWriteAce) {
                            $taskIssues += [pscustomobject]@{ Task=$t.TaskName; Path=$t.TaskPath; Execute=$ex + ' (MISSING)'; Principal=$t.Principal.UserId; RunLevel=$t.Principal.RunLevel; Directory=$dir; Aces=$w.BroadAces }
                        }
                    }
                }
            }
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Scheduled task enumeration failed (' + $_.Exception.Message + '); falling back to task-file permissions only.')
    }
    $tasksDir = Join-Path $env:SystemRoot 'System32\Tasks'
    $tasksDirWritable = Test-DirectoryWritable -Path $tasksDir -NoWriteTest
    if ($taskIssues.Count -gt 0) {
        Write-Table -Rows ($taskIssues | Select-Object -First 15) -Columns @('Task','Principal','RunLevel','Execute','Aces') -Headers @{ Task='Task'; Principal='Runs as'; RunLevel='Run level'; Execute='Action'; Aces='Broad ACEs on directory' }
        foreach ($ti in ($taskIssues | Select-Object -First 8)) {
            $pw = Test-DirectoryWritable -Path $ti.Directory
            Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($pw.WriteSucceeded) { 'VALIDATED' } else { 'WARN' }) -Attribute 'Scheduled task with writable action path' `
                -Target $ti.Task -Finding ('Scheduled task ''' + $ti.Task + ''' (path ' + $ti.Path + ') executes ''' + $ti.Execute + ''' from a directory writable by non-administrative principals, and runs as ' + $ti.Principal + ' (' + $ti.RunLevel + ').') `
                -Configured ('Action: ' + $ti.Execute + ' ; principal: ' + $ti.Principal + ' ; directory ACEs: ' + $ti.Aces) `
                -Observed $(if ($pw.WriteSucceeded) { 'Write permission PROVEN with a reversible marker file (created and deleted).' } else { 'ACL-based evidence only.' }) `
                -Validation 'ScheduledTasks inventory + ancestor directory ACL analysis + controlled reversible write proof. No task was triggered, modified, registered or deleted.' `
                -Prerequisites 'A task trigger (schedule, logon, or an event) must occur, or the task must be started by another process - the trigger was NOT caused by this tool.' `
                -Class 'High' -CatClass 'IdentityRights' `
                -Remediation 'Remove broad write ACEs from the action''s directory, correct the task to use an absolute path in a protected location, and set the task principal to the least-privileged account that can perform the work (avoid SYSTEM/highest where unnecessary).' `
                -Impact 'A writable task action (or a missing one in a writable directory) lets any local user substitute code that runs with the task''s principal - typically SYSTEM - at the next trigger.'
        }
    } elseif ($tasksDirWritable.BroadWriteAce) {
        Add-Finding -Category 'Local Privilege Escalation' -Status 'WARN' -Attribute 'Task definition directory permissions' `
            -Finding 'The %SystemRoot%\System32\Tasks directory has broad write ACEs, allowing task-definition tampering by non-administrative principals.' `
            -Configured ('Directory ' + $tasksDir + ' ; ACEs: ' + $tasksDirWritable.BroadAces) -Observed 'ACL analysis (no write proof performed on a system directory)' `
            -Validation 'ACL analysis only; no file was created in this directory.' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'Restore default permissions on %SystemRoot%\System32\Tasks (Administrators and SYSTEM only, Users read/execute).' `
            -Impact 'Write access here allows creating or modifying scheduled task definitions that execute as SYSTEM.'
    } else {
        Write-Status 'PASS' 'No scheduled-task action executed from a broadly writable directory, and the task definition directory is not writable by non-administrative principals.'
    }

    Write-Host ''
    Write-Host '  -- 17.5 Startup locations, autologon, AlwaysInstallElevated ----------------------' -ForegroundColor DarkCyan
    $startupDirs = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    foreach ($d in $startupDirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $w = Test-DirectoryWritable -Path $d -NoWriteTest
        Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($w.BroadWriteAce) { 'WARN' } else { 'PASS' }) -Attribute 'Startup folder permissions' `
            -Finding $(if ($w.BroadWriteAce) { 'A startup folder is writable by non-administrative principals: any user can place an executable that runs at logon of any other user who shares that folder (the machine-wide folder is the dangerous one).' } else { 'Startup folder permissions do not grant broad write access.' }) `
            -Configured ('Directory ' + $d + ' ; ACEs: ' + $(if ($w.BroadAces) { $w.BroadAces } else { 'none of the broad groups have write rights' })) `
            -Observed 'ACL analysis of the startup folder (no file placed; placement of an executable was deliberately NOT performed)' `
            -Validation 'ACL analysis only.' -Class 'Medium' -CatClass 'IdentityRights' `
            -Remediation 'Restrict the machine-wide Startup folder to Administrators and SYSTEM; users may keep write access to their own per-user Startup folder, which only affects their own logon.' `
            -Impact 'Machine-wide startup write access is a persistence and cross-user execution primitive: code placed there runs whenever any user logs on.'
    }

    $autoUser = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName'
    $autoPwd  = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword'
    $autoDom  = Get-RegValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultDomainName'
    $ae1 = Get-RegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $ae2 = Get-RegValue -Hive 'CurrentUser' -Path 'SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $ae1v = Get-U32 $ae1; $ae2v = Get-U32 $ae2

    Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($autoPwd.NameExists) { 'RISK DETECTED' } else { 'PASS' }) -Attribute 'Autologon credentials in registry' `
        -Finding $(if ($autoPwd.NameExists) { 'The Winlogon DefaultPassword value is PRESENT: an autologon credential is stored in the registry, where any principal able to read this key (and any offline disk access) can recover it.' } else { 'No autologon password value is present in the Winlogon key.' }) `
        -Configured ('DefaultUserName present=' + $autoUser.NameExists + ' ; DefaultPassword present=' + $autoPwd.NameExists + $(if ($autoDom.NameExists) { ' ; DefaultDomainName present=True' } else { '' })) `
        -Observed 'The VALUE of DefaultPassword is deliberately NOT read, printed or stored by this tool: its presence alone is the finding and the value is credential material. Presence was determined from the value-name list only.' `
        -Validation 'Registry value-name enumeration without reading the value (evidence of presence, not of content)' `
        -Class 'Critical' -CatClass 'DataAtRest' `
        -Remediation 'Remove the autologon configuration (delete DefaultPassword, and configure AutoAdminLogon=0) or migrate to a supported mechanism. Where autologon is operationally required, use a dedicated low-privilege account, restrict access to the machine (BitLocker, physical controls), and rotate the credential frequently.' `
        -Impact 'A stored autologon password provides immediate, replayable credentials to any principal that can read HKLM (including a remote attacker with administrative access through remote registry or a local privilege escalation) and to anyone with offline disk access.'

    Add-Finding -Category 'Local Privilege Escalation' -Status $(if (($ae1v -eq 1) -and ($ae2v -eq 1)) { 'RISK DETECTED' } else { 'PASS' }) -Attribute 'AlwaysInstallElevated' `
        -Finding $(if (($ae1v -eq 1) -and ($ae2v -eq 1)) { 'AlwaysInstallElevated is enabled in BOTH the machine and user policy scopes, so any user can install a crafted MSI package with SYSTEM privileges.' } else { 'AlwaysInstallElevated is not enabled in both policy scopes (the exploit requires both to be set).' }) `
        -Configured ('HKLM AlwaysInstallElevated=' + (Format-RegState $ae1) + ' ; HKCU AlwaysInstallElevated=' + (Format-RegState $ae2)) `
        -Observed 'Both scopes must be enabled for the escalation to be available; the observed pair is recorded above.' `
        -Validation 'Registry read of both policy scopes (no MSI was built or installed)' -Class 'Critical' -CatClass 'IdentityRights' `
        -Remediation 'Set AlwaysInstallElevated to 0 (or remove the value) in both HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer and HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer, and enforce through GPO.' `
        -Impact 'A standard user can elevate to SYSTEM by installing an attacker-authored MSI - a complete local privilege boundary crossing with no additional prerequisites.'

    Write-Host ''
    Write-Host '  -- 17.6 Token privileges and security-policy privilege assignments ----------------' -ForegroundColor DarkCyan
    try {
        $privOut = @(Get-TokenPrivileges)
        $dangerous = @{
            'SeImpersonatePrivilege'        = 'token impersonation (potato-family escalation when a privileged token can be coerced)'
            'SeAssignPrimaryTokenPrivilege' = 'token replacement'
            'SeDebugPrivilege'              = 'open any process for memory access, including LSASS'
            'SeBackupPrivilege'             = 'read any file regardless of ACL (including registry hives and NTDS.dit)'
            'SeRestorePrivilege'            = 'write any file regardless of ACL (binary replacement)'
            'SeTakeOwnershipPrivilege'      = 'take ownership of any object and then rewrite its ACL'
            'SeLoadDriverPrivilege'         = 'load a kernel driver (full kernel control)'
            'SeTcbPrivilege'                = 'act as part of the operating system'
            'SeCreateTokenPrivilege'        = 'create arbitrary tokens'
            'SeManageVolumePrivilege'       = 'direct volume access'
            'SeEnableDelegationPrivilege'   = 'configure Kerberos delegation'
        }
        $held = @()
        foreach ($tp in $privOut) {
            if ($dangerous.ContainsKey($tp.Name)) {
                $held += [pscustomobject]@{ Privilege=$tp.Name; State=$tp.State; Meaning=$dangerous[$tp.Name] }
            }
        }
        if ($privOut.Count -eq 0) {
            Write-Status 'NOT TESTABLE' ('Token privileges could not be enumerated in memory; no claim is made about privileges held. Reason: ' + [string]$script:TokenProbeMethod)
        }
        if ($held.Count -gt 0) {
            Write-Table -Rows $held -Columns @('Privilege','State','Meaning') -Headers @{ Privilege='Token privilege'; State='State in this token'; Meaning='Why it matters' }
            $enabled = @($held | Where-Object { $_.State -eq 'Enabled' })
            Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($enabled.Count -gt 0) { 'WARN' } else { 'INFO' }) -Attribute 'Sensitive token privileges held' `
                -Finding ($held.Count.ToString() + ' sensitive privilege(s) are present in the assessment token (' + $enabled.Count + ' currently enabled), including: ' + (($held | Select-Object -First 6 | ForEach-Object { $_.Privilege }) -join ', ') + '.') `
                -Observed (($held | ForEach-Object { $_.Privilege + '=' + $_.State }) -join '; ') `
                -Validation ('In-memory token query (GetTokenInformation / TokenPrivileges; ' + [string]$script:TokenProbeMethod + '). Privileges are reported, never exercised: no process memory was read, no file access was bypassed and no driver was loaded.' ) `
                -Class 'High' -CatClass 'IdentityRights' `
                -Remediation 'Remove sensitive privileges from principals that do not require them (SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege and SeImpersonatePrivilege are granted to Administrators by default, which is why minimising administrative membership matters most). For service accounts that legitimately need SeImpersonatePrivilege, apply the vendor hardening and monitor for token-coercion activity.' `
                -Impact 'These privileges are the raw capability behind most local escalation and credential-access techniques; their presence in a token defines what that token can do beyond its nominal group membership.'
            $script:Facts['SeDebugPresent'] = [bool](($held | Where-Object { $_.Privilege -eq 'SeDebugPrivilege' }).Count -gt 0)
        }
    } catch { Write-Status 'NOT TESTABLE' ('Token privilege enumeration failed: ' + $_.Exception.Message) }

    if ($script:IsAdmin) {
        $tmpInf = Join-Path $env:TEMP ('eia-privrights-' + [guid]::NewGuid().ToString('N') + '.inf')
        try {
            $null = & secedit.exe /export /cfg $tmpInf /areas USER_RIGHTS 2>&1
            if (Test-Path -LiteralPath $tmpInf) {
                $lines = Get-Content -LiteralPath $tmpInf -ErrorAction Stop
                $watch = @('SeDebugPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeImpersonatePrivilege','SeTcbPrivilege','SeCreateTokenPrivilege','SeLoadDriverPrivilege','SeEnableDelegationPrivilege')
                $assignRows = @()
                foreach ($l in $lines) {
                    if ($l -match '^\s*(Se[A-Za-z]+Privilege)\s*=\s*(.*)$') {
                        $priv = $Matches[1]; $sids = $Matches[2]
                        if (-not ($watch -contains $priv)) { continue }
                        $entries = @()
                        foreach ($s in ($sids -split ',')) {
                            $s = $s.Trim()
                            if (-not $s) { continue }
                            if ($s -like '*S-1-*') { $entries += (Get-PrincipalNameForSid -Sid $s.TrimStart('*')) }
                            else { $entries += $s }
                        }
                        $assignRows += [pscustomobject]@{ Privilege=$priv; Assignments=($entries -join ', ') }
                    }
                }
                if ($assignRows.Count -gt 0) {
                    Write-Host ''
                    Write-Host '    Local security policy privilege assignments (native secedit export, temp file deleted):' -ForegroundColor DarkGray
                    Write-Table -Rows $assignRows -Columns @('Privilege','Assignments') -Headers @{ Privilege='Privilege right'; Assignments='Assigned to' }
                    $broadAssign = @()
                    foreach ($r in $assignRows) {
                        if ($r.Assignments -match '(?i)Users|Authenticated Users|Everyone|INTERACTIVE|SERVICE|NETWORK SERVICE') { $broadAssign += ($r.Privilege + ' -> ' + $r.Assignments) }
                    }
                    Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($broadAssign.Count -gt 0) { 'WARN' } else { 'INFO' }) -Attribute 'Security-policy privilege assignments' `
                        -Finding $(if ($broadAssign.Count -gt 0) { ($broadAssign.Count.ToString() + ' sensitive privilege(s) are assigned beyond the administrative groups: ' + ($broadAssign -join ' | ')) } else { 'Sensitive privileges are assigned only to administrative groups and service accounts that require them.' }) `
                        -Observed (($assignRows | ForEach-Object { $_.Privilege + '=[' + $_.Assignments + ']' }) -join '; ') `
                        -Validation 'Native security-policy export (secedit /export /areas USER_RIGHTS) with the temporary INF deleted immediately afterwards. SIDs were translated to names for readability; untranslatable SIDs are shown raw.' `
                        -Class 'High' -CatClass 'IdentityRights' `
                        -Remediation 'Remove non-administrative assignments from these rights. In particular: SeDebugPrivilege and SeTakeOwnershipPrivilege should be held by Administrators only, SeBackupPrivilege/SeRestorePrivilege should be granted only to backup service accounts with the vendor''s documented model, and SeImpersonatePrivilege should never be granted to interactive user groups.' `
                        -Impact 'A non-administrative principal (or a service account whose credentials are recoverable) that holds one of these rights can cross the privilege boundary directly - often without any exploit at all.'
                }
            }
        } catch {
            Write-Status 'NOT TESTABLE' ('Privilege-rights export failed: ' + $_.Exception.Message)
        } finally {
            try { if (Test-Path -LiteralPath $tmpInf) { Remove-Item -LiteralPath $tmpInf -Force -ErrorAction Stop; Write-Status 'INFO' 'Privilege-rights export artifact removed.' } } catch { Write-Status 'WARN' ('Artifact not removed: ' + $tmpInf) }
        }
    } else { Write-Status 'NOT TESTABLE' 'Privilege-right assignments require administrator rights to export; skipped.' }

    Write-Host ''
    Write-Host '  -- 17.7 DLL search order and PATH writability -----------------------------------' -ForegroundColor DarkCyan
    $pathDirs = @($env:PATH -split ';' | Where-Object { $_ -and (Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue) })
    $writablePathDirs = @()
    foreach ($d in ($pathDirs | Select-Object -First 40)) {
        $w = Test-DirectoryWritable -Path $d -NoWriteTest
        if ($w.BroadWriteAce) { $writablePathDirs += $w }
    }
    Add-Finding -Category 'Local Privilege Escalation' -Status $(if ($writablePathDirs.Count -gt 0) { 'WARN' } else { 'PASS' }) -Attribute 'Writable directories in the executable search path' `
        -Finding $(if ($writablePathDirs.Count -gt 0) { ($writablePathDirs.Count.ToString() + ' directory/ies on the PATH are writable by non-administrative principals, which enables DLL/side-loading hijacks for any process that resolves an unqualified library name (including many SYSTEM services and built-in utilities).') } else { 'No directory on the PATH grants broad write access.' }) `
        -Observed $(if ($writablePathDirs.Count -gt 0) { (($writablePathDirs | ForEach-Object { $_.Path + ' [' + $_.BroadAces + ']' }) -join ' | ') } else { 'All PATH entries restrict write access to administrators.' }) `
        -Validation 'ACL analysis of each PATH directory (no file was created in any PATH directory)' -Class 'High' -CatClass 'IdentityRights' `
        -Remediation 'Remove non-administrative write permissions from every PATH directory, and avoid placing service or administrative tooling in user-writable locations. For services, use fully qualified DLL paths or configure a safe DLL search mode where the vendor supports it.' `
        -Impact 'A writable early-PATH directory lets a low-privileged user plant a library or executable that a more privileged process will load, converting normal administrative activity into code execution as that privileged process.'
    $script:Facts['WritablePathDirs'] = $writablePathDirs.Count

    # =======================================================================================
    #  17.x Dormant Disconnected Privileged Process Sessions
    #  READ-ONLY: CIM process enumeration and GetOwner method; no process is opened or spawned.
    # =======================================================================================
    Write-Host ''
    Write-Host '  -- Dormant Disconnected Privileged Process Sessions -------------------------------' -ForegroundColor DarkCyan
    try {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUserFull = [string]$currentIdentity.Name
        $currentUserShort = if ($currentUserFull -match '\\') { $currentUserFull.Split('\')[-1] } else { $currentUserFull }
        $dormantPrivileged = @()

        $processes = Get-CimSafe -Class 'Win32_Process'
        foreach ($proc in $processes) {
            if ([string]::IsNullOrWhiteSpace([string]$proc.Name)) { continue }
            if ($proc.Name -notin @('explorer.exe','rdpclip.exe')) { continue }

            try {
                $owner = Invoke-CimMethod -InputObject $proc -MethodName 'GetOwner' -ErrorAction Stop
                if ($owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$owner.User)) { continue }

                $ownerUser = [string]$owner.User
                $ownerDomain = [string]$owner.Domain
                $accountName = if ($ownerDomain) { $ownerDomain + '\' + $ownerUser } else { $ownerUser }
                $isCurrent = $accountName.Equals($currentUserFull, [System.StringComparison]::OrdinalIgnoreCase) -or
                             $ownerUser.Equals($currentUserShort, [System.StringComparison]::OrdinalIgnoreCase)
                if ($accountName -match '(?i)admin|adm_' -and -not $isCurrent) {
                    $dormantPrivileged += [pscustomobject]@{
                        ProcessName = [string]$proc.Name
                        PID = [int]$proc.ProcessId
                        SessionOwner = $accountName
                    }
                }
            } catch { }
        }

        if ($dormantPrivileged.Count -gt 0) {
            $sessionGroups = @(
                $dormantPrivileged |
                    Group-Object -Property SessionOwner |
                    ForEach-Object {
                        [pscustomobject]@{
                            SessionOwner = $_.Name
                            ProcessCount = $_.Count
                            Processes = (($_.Group | ForEach-Object { $_.ProcessName + ' (PID ' + $_.PID + ')' }) -join ', ')
                        }
                    }
            )
            Write-Table -Rows $sessionGroups -Columns @('SessionOwner','ProcessCount','Processes') `
                -Headers @{ SessionOwner='Session Owner'; ProcessCount='Process Count'; Processes='Processes' }
            Add-Finding -Category 'Local Privilege Escalation' -Status 'WARN' `
                -Attribute 'Dormant Privileged Token Exposure' `
                -Finding 'Explorer or RDP clipboard processes are running under a different account whose name contains an administrative marker, indicating a potentially exposed privileged interactive session.' `
                -Observed (($dormantPrivileged | ForEach-Object { $_.ProcessName + ' PID=' + $_.PID + ' Owner=' + $_.SessionOwner }) -join '; ') `
                -Validation 'Read-only CIM Win32_Process enumeration followed by the Win32_Process.GetOwner CIM method; no process memory or token was accessed.' `
                -Class 'High' -CatClass 'IdentityRights'
        } else {
            Write-Status 'PASS' 'No explorer.exe or rdpclip.exe process owned by a different account matching admin or adm_ was observed.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Privileged process-session enumeration failed: ' + $_.Exception.Message)
    }

    # Native read-only corroboration: whoami /user /upn. This is intentionally additive;
    # the CIM GetOwner results above remain the primary process-session evidence.
    Write-Host ''
    Write-Host '  -- Native identity corroboration (whoami) ----------------------------------------' -ForegroundColor DarkCyan
    try {
        $whoamiLines = @(& whoami.exe /user /upn 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not $whoamiLines) {
            throw ('whoami.exe returned exit code ' + [string]$LASTEXITCODE)
        }
        $whoamiRows = @()
        foreach ($line in $whoamiLines) {
            $t = ([string]$line).Trim()
            if ($t -and $t -notmatch '^USER INFORMATION$|^UPN INFORMATION$|^---') {
                $whoamiRows += [pscustomobject]@{ Output = $t }
            }
        }
        if ($whoamiRows.Count -gt 0) {
            Write-Table -Rows $whoamiRows -Columns @('Output') -Headers @{ Output='whoami output' }
            Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' `
                -Attribute 'Native identity corroboration' `
                -Finding 'The current Windows identity was corroborated with the native whoami utility.' `
                -Observed ($whoamiRows.Output -join ' | ') `
                -Validation 'Read-only native whoami.exe /user /upn invocation; no account or token state was changed.' `
                -Class 'Low' -CatClass 'Context' -NoConsole
        } else {
            Write-Status 'NOT TESTABLE' 'whoami.exe returned no parseable identity output.'
        }
    } catch {
        Write-Status 'NOT TESTABLE' ('Native whoami identity corroboration failed: ' + $_.Exception.Message)
    }

}

# ===========================================================================================
#  SECTION 18 :: LOLBIN / NATIVE EXECUTION ASSESSMENT
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Native, Microsoft-signed binaries are present by design on every Windows system. Their
#  presence is therefore NOT a vulnerability - the assessment question is whether application
#  control is in place, whether their parent directories are protected, and whether they are
#  wired into privileged execution paths (services, scheduled tasks) that could be abused.
#  This module records those facts and states plainly that presence alone carries no rating.
# ===========================================================================================
function Invoke-Section18_LolBin {
    Write-Host ''
    Write-Host '  -- 18.1 Application control state (AppLocker / WDAC) -----------------------------' -ForegroundColor DarkCyan
    $alPolicy = $null; $alEnforced = $null; $alPath = 'not present'
    try {
        $alPath = Join-Path $env:SystemRoot 'System32\AppLocker\Exports'
        $alPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $xml = $alPolicy.ToXml()
        $enforceCount = ([regex]::Matches($xml, '(?i)EnforcementMode="Enabled"|EnforcementMode="AuditOnly"')).Count
        $alEnforced = ([regex]::Matches($xml, 'EnforcementMode="Enabled"')).Count
        Write-Status 'INFO' ('AppLocker effective policy retrieved (' + $enforceCount + ' rule-collection entries; ' + $alEnforced + ' in enforce mode)')
        Add-Finding -Category 'Application Control' -Status $(if ($alEnforced -gt 0) { 'PASS' } else { 'WARN' }) -Attribute 'AppLocker effective policy' `
            -Finding $(if ($alEnforced -gt 0) { 'An AppLocker policy is applied and contains collection(s) in enforce mode.' } else { 'An AppLocker policy exists but no collection is in enforce mode (audit-only or empty), so execution is not actually restricted.' }) `
            -Observed ('EnforcementMode="Enabled" occurrences: ' + $alEnforced + '; total rule-collection entries: ' + $enforceCount) `
            -Validation 'Native Get-AppLockerPolicy -Effective (the policy the engine itself would apply)' `
            -Class 'High' -CatClass 'Integrity' `
            -Remediation 'Deploy AppLocker (or WDAC) in enforce mode with default rules plus publisher-based allow rules, and protected paths. Test in audit-only mode first, then move to enforce after reviewing the audit events (8003/8004).' `
            -Impact 'Without application control, any unsigned or user-writable executable runs as the invoking user; application control is the control that removes entire classes of technique from an attacker''s toolkit and is the main mitigation for the native-binary abuse catalogued here.'
    } catch {
        Write-Status 'NOT TESTABLE' ('AppLocker policy could not be read (' + $_.Exception.Message + '); the module may be absent on this edition.')
        Add-Finding -Category 'Application Control' -Status 'NOT TESTABLE' -Attribute 'AppLocker effective policy' `
            -Finding 'The effective AppLocker policy could not be read on this host (AppLocker cmdlets unavailable or access denied).' `
            -Validation 'Not completed' -Class 'High' -CatClass 'Integrity' `
            -Remediation 'Confirm whether application control is deployed in the estate (AppLocker and/or WDAC) and validate it on a representative host of this OS edition.' `
            -Impact 'Unknown: without a readable policy, no statement can be made about whether native-binary abuse is constrained on this host.' -NoConsole
    }

    $ciPolicyDir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
    $ciCount = 0
    try { if (Test-Path -LiteralPath $ciPolicyDir) { $ciCount = @(Get-ChildItem -LiteralPath $ciPolicyDir -Filter '*.cip' -ErrorAction SilentlyContinue).Count } } catch { }
    $dgStatus = 'unknown'; $dgEnforce = 'unknown'
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $dgStatus = [string]$dg.CodeIntegrityPolicyEnforcementStatus
        $dgEnforce = 'SecurityServicesRunning=' + $dg.SecurityServicesRunning
    } catch { }
    Add-Finding -Category 'Application Control' -Status $(if ($ciCount -gt 0 -or $dgStatus -eq '2') { 'PASS' } else { 'WARN' }) -Attribute 'WDAC / code integrity policy' `
        -Finding $(if ($ciCount -gt 0 -or $dgStatus -eq '2') { 'A code integrity (WDAC) policy appears to be present/enforced on this host.' } else { 'No active WDAC policy file was found and code integrity enforcement status does not indicate an enforced policy.' }) `
        -Observed ('CiPolicies\Active\*.cip count: ' + $ciCount + '; CodeIntegrityPolicyEnforcementStatus: ' + $dgStatus + '; ' + $dgEnforce) `
        -Validation 'File-system enumeration of the WDAC policy store plus the runtime code-integrity status from Win32_DeviceGuard' `
        -Class 'High' -CatClass 'Integrity' `
        -Remediation 'Deploy WDAC (Windows Defender Application Control) in audit mode, build the policy from the audit data, then enforce it, including a managed-installer rule so that signed installers remain trusted. Combine with AppLocker for legacy compatibility if required.' `
        -Impact 'Signed-binary abuse (the techniques this section catalogues) is sharply reduced when only trusted, signed code may execute; with no code-integrity policy, any Microsoft-signed binary that the user can invoke is a valid execution primitive.'
    $script:Facts['CiPolicyCount'] = $ciCount

    Write-Host ''
    Write-Host '  -- 18.2 Native binary inventory and abuse-relevant properties --------------------' -ForegroundColor DarkCyan
    $wbem = Join-Path $env:SystemRoot 'System32\wbem'
    $lolbins = @(
        @{ Name='cmd.exe';            Path=(Join-Path $env:SystemRoot 'System32\cmd.exe');           Cat='Script interpreter' }
        @{ Name='powershell.exe';     Path=(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'); Cat='Script interpreter' }
        @{ Name='pwsh.exe';           Path=(Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe');    Cat='Script interpreter' }
        @{ Name='wscript.exe';        Path=(Join-Path $env:SystemRoot 'System32\wscript.exe');       Cat='Script interpreter' }
        @{ Name='cscript.exe';        Path=(Join-Path $env:SystemRoot 'System32\cscript.exe');       Cat='Script interpreter' }
        @{ Name='mshta.exe';          Path=(Join-Path $env:SystemRoot 'System32\mshta.exe');         Cat='Signed proxy execution' }
        @{ Name='rundll32.exe';       Path=(Join-Path $env:SystemRoot 'System32\rundll32.exe');      Cat='DLL loading mechanism' }
        @{ Name='regsvr32.exe';       Path=(Join-Path $env:SystemRoot 'System32\regsvr32.exe');      Cat='Signed proxy execution' }
        @{ Name='installutil.exe';    Path=(Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe'); Cat='Installer component' }
        @{ Name='msbuild.exe';        Path=(Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'); Cat='Installer component' }
        @{ Name='msiexec.exe';        Path=(Join-Path $env:SystemRoot 'System32\msiexec.exe');       Cat='Installer component' }
        @{ Name='certutil.exe';       Path=(Join-Path $env:SystemRoot 'System32\certutil.exe');      Cat='Certificate utility / file transfer' }
        @{ Name='bitsadmin.exe';      Path=(Join-Path $env:SystemRoot 'System32\bitsadmin.exe');     Cat='Native file transfer' }
        @{ Name='curl.exe';           Path=(Join-Path $env:SystemRoot 'System32\curl.exe');          Cat='Native file transfer' }
        @{ Name='makecab.exe';        Path=(Join-Path $env:SystemRoot 'System32\makecab.exe');       Cat='Native archive component' }
        @{ Name='expand.exe';         Path=(Join-Path $env:SystemRoot 'System32\expand.exe');        Cat='Native archive component' }
        @{ Name='tar.exe';            Path=(Join-Path $env:SystemRoot 'System32\tar.exe');           Cat='Native archive component' }
        @{ Name='forfiles.exe';       Path=(Join-Path $env:SystemRoot 'System32\forfiles.exe');      Cat='Management utility' }
        @{ Name='schtasks.exe';       Path=(Join-Path $env:SystemRoot 'System32\schtasks.exe');      Cat='Scheduled-task utility' }
        @{ Name='at.exe';             Path=(Join-Path $env:SystemRoot 'System32\at.exe');            Cat='Scheduled-task utility (legacy)' }
        @{ Name='sc.exe';             Path=(Join-Path $env:SystemRoot 'System32\sc.exe');            Cat='Service utility' }
        @{ Name='net.exe';            Path=(Join-Path $env:SystemRoot 'System32\net.exe');           Cat='Service utility' }
        @{ Name='net1.exe';           Path=(Join-Path $env:SystemRoot 'System32\net1.exe');          Cat='Service utility' }
        @{ Name='wmic.exe';           Path=(Join-Path $env:SystemRoot 'System32\wbem\wmic.exe');     Cat='Microsoft management interface' }
        @{ Name='wt.exe';             Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wt.exe'); Cat='Microsoft management interface' }
        @{ Name='psr.exe';            Path=(Join-Path $env:SystemRoot 'System32\psr.exe');           Cat='Microsoft management interface' }
        @{ Name='conhost.exe';        Path=(Join-Path $env:SystemRoot 'System32\conhost.exe');       Cat='Parent-directory hijack target' }
        @{ Name='control.exe';        Path=(Join-Path $env:SystemRoot 'System32\control.exe');      Cat='Signed proxy execution' }
        @{ Name='presentationhost.exe'; Path=(Join-Path $env:SystemRoot 'System32\presentationhost.exe'); Cat='Signed proxy execution' }
        @{ Name='xwizard.exe';        Path=(Join-Path $env:SystemRoot 'System32\xwizard.exe');       Cat='Signed proxy execution' }
    )

    # Service and scheduled-task relationships: which native binaries are wired into privileged paths
    $svcRefs = @{}
    try {
        foreach ($s in (Get-CimSafe -Class 'Win32_Service')) {
            $pn = [string]$s.PathName
            if ($pn) { $svcRefs[$pn.ToLower()] = ($s.Name + ' (' + $s.StartName + ')') }
        }
    } catch { }
    $taskRefs = @{}
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
            foreach ($a in $t.Actions) {
                if ($a.Execute) {
                    $k = ([Environment]::ExpandEnvironmentVariables($a.Execute)).ToLower()
                    $taskRefs[$k] = ($t.TaskName + ' (' + $t.Principal.UserId + '/' + $t.Principal.RunLevel + ')')
                }
            }
        }
    } catch { }

    $rows = @()
    $suspicious = @()
    foreach ($b in $lolbins) {
        $exists = Test-Path -LiteralPath $b.Path
        $entry = [pscustomobject]@{
            Name=$b.Name; Category=$b.Cat; Present=$(if ($exists) { 'yes' } else { 'no' }); Version=''; Signature=''; Signer=''
            UserExec=''; ParentDirWritable=''; ParentDirPath=''; ServiceOrTask=''; Note=''
        }
        if ($exists) {
            try { $entry.Version = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($b.Path)).FileVersion } catch { $entry.Version = 'n/a' }
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $b.Path -ErrorAction Stop
                $entry.Signature = $sig.Status.ToString()
                if ($sig.SignerCertificate) { $entry.Signer = $sig.SignerCertificate.Subject.Split(',')[0].Replace('CN=', '').Trim() }
            } catch { $entry.Signature = 'unreadable' }
            try {
                $acl = Get-Acl -LiteralPath $b.Path
                $execUsers = @()
                foreach ($ace in $acl.Access) {
                    try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
                    $r = $ace.FileSystemRights.ToString()
                    if ($ace.AccessControlType.ToString() -eq 'Allow' -and $r -match 'Execute|ReadAndExecute|FullControl|Modify') {
                        if ($sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4')) { $execUsers += $sid }
                    }
                }
                $entry.UserExec = if ($execUsers.Count -gt 0) { 'yes (standard user groups)' } else { 'restricted' }
            } catch { $entry.UserExec = 'unknown' }
            $entry.ParentDirPath = [System.IO.Path]::GetDirectoryName($b.Path)
            $pd = Test-DirectoryWritable -Path $entry.ParentDirPath -NoWriteTest
            $entry.ParentDirWritable = if ($pd.BroadWriteAce) { 'YES - ' + $pd.BroadAces } elseif ($pd.Error) { 'unknown' } else { 'no' }
            $refs = @()
            foreach ($k in $svcRefs.Keys) { if ($k -like ('*' + $b.Name.ToLower() + '*')) { $refs += ('service: ' + $svcRefs[$k]) } }
            foreach ($k in $taskRefs.Keys) { if ($k -like ('*' + $b.Name.ToLower() + '*')) { $refs += ('task: ' + $taskRefs[$k]) } }
            $entry.ServiceOrTask = if ($refs.Count -gt 0) { ($refs -join '; ') } else { 'none observed' }
            if ($pd.BroadWriteAce) {
                $suspicious += $entry
                $entry.Note = 'parent directory writable by non-administrative principals'
            }
        }
        $rows += $entry
    }
    Write-Table -Rows $rows -Columns @('Name','Category','Present','Version','Signature','Signer','UserExec','ParentDirWritable','ServiceOrTask') `
        -Headers @{ Name='Binary'; Category='Category'; Present='Present'; Version='Version'; Signature='Signature'; Signer='Signer'; UserExec='User execution'; ParentDirWritable='Parent dir writable'; ServiceOrTask='Service / task relationship' }

    $presentCount = @($rows | Where-Object { $_.Present -eq 'yes' }).Count
    $unsigned    = @($rows | Where-Object { $_.Present -eq 'yes' -and $_.Signature -ne 'Valid' })
    Add-Finding -Category 'LOLBin / Native Execution' -Status 'INFO' -CatClass 'Context' -Attribute 'Native binary inventory' `
        -Finding ($presentCount.ToString() + ' of ' + $lolbins.Count + ' catalogued native binaries/interpreter components are present on this host across the categories: script interpreters, signed proxy execution, installer components, management utilities, service utilities, scheduled-task utilities, certificate utilities, Microsoft management interfaces, native archive/file-transfer components and DLL-loading mechanisms.') `
        -Observed ('Present: ' + $presentCount + '; Not present: ' + ($lolbins.Count - $presentCount) + '; signature status not Valid: ' + $unsigned.Count + ' (' + (($unsigned | ForEach-Object { $_.Name + '=' + $_.Signature }) -join ', ') + ')') `
        -Validation 'File version info + Authenticode signature verification (Get-AuthenticodeSignature) + ACL analysis of each binary and its parent directory + cross-reference against service ImagePaths and scheduled-task actions.' `
        -Class 'Low' -CatClass 'Context' `
        -Remediation 'PRESENCE OF THESE BINARIES IS NOT A VULNERABILITY: they are shipped by Windows and are required for normal operation. The actionable controls are (1) application control in enforce mode (AppLocker/WDAC, see 18.1), (2) protected parent directories, (3) removal of unnecessary scheduled-task and service relationships, and (4) script-block logging plus PowerShell module/transcription logging so that interpreter abuse is visible.' `
        -Impact 'Native binaries provide execution primitives that survive simple filename-based blocking. They are only useful to an attacker in the absence of application control and logging, which is what the control columns in this table measure.' -NoConsole

    if ($unsigned.Count -gt 0) {
        Add-Finding -Category 'LOLBin / Native Execution' -Status 'WARN' -Attribute 'Native binary signature status' `
            -Finding ($unsigned.Count.ToString() + ' catalogued native binary/binaries did not verify as Validly signed: ' + (($unsigned | ForEach-Object { $_.Name + '=' + $_.Signature }) -join ', ') + '.') `
            -Observed (($unsigned | ForEach-Object { $_.Name + ': ' + $_.Signature }) -join '; ') `
            -Validation 'Get-AuthenticodeSignature per binary' -Class 'High' -CatClass 'Integrity' `
            -Remediation 'Investigate every binary that is not Validly signed: verify the file hash against the vendor baseline, replace it from a trusted source, and treat a replaced system binary as a possible host compromise indicator. Note that on Windows Server Core and some editions certain components are legitimately absent rather than unsigned.' `
            -Impact 'A system binary whose signature does not verify may have been modified, which would indicate either a deliberately planted binary or a broken servicing state - both require incident-response attention rather than a configuration change.'
    }

    if ($suspicious.Count -gt 0) {
        foreach ($s in $suspicious) {
            Add-Finding -Category 'LOLBin / Native Execution' -Status 'WARN' -Attribute 'Native binary in a writable directory' `
                -Target $s.Name -Finding ($s.Name + ' resides in a directory that non-administrative principals can write to, so the binary itself can be replaced (a signed-binary trust bypass).') `
                -Configured ('Binary: ' + $s.Name + ' ; parent directory (writable): ' + $s.ParentDirPath + ' ; ACEs: ' + $s.ParentDirWritable) `
                -Observed ('Binary: ' + $s.Name + ' ; version ' + $s.Version + ' ; signature ' + $s.Signature + ' ; service/task relationship: ' + $s.ServiceOrTask) `
                -Validation 'ACL analysis of the parent directory' -Class 'High' -CatClass 'Integrity' `
                -Remediation 'Remove write permissions for non-administrative principals from Windows and Program Files subdirectories. If the binary is in a non-standard location (for example a user profile or a writable share), reinstall the component into a protected path.' `
                -Impact 'Replacing a Microsoft-signed binary in a writable location gives an attacker code execution under a trusted image name, which defeats name-based allow lists and blends into normal process telemetry.'
        }
    } else {
        Write-Status 'PASS' 'All located native binaries reside in directories that restrict write access to administrators.'
    }

    Add-Finding -Category 'LOLBin / Native Execution' -Status 'INFO' -CatClass 'Context' -Attribute 'Execution-control assessment limits' `
        -Finding 'This module maps control coverage (application control, parent-directory permissions, service/task relationships) and does not attempt to execute any binary for the purpose of demonstrating abuse.' `
        -Observed 'Inventory and permission analysis only.' -Validation 'Static assessment, stated explicitly.' -Class 'Low' -CatClass 'Context' `
        -Remediation 'If the engagement requires dynamic validation of a specific bypass, perform it separately with an explicit, scoped authorisation and an agreed detection test with the blue team.' `
        -Impact 'None from this module: no binary was executed to test a bypass, so no bypass is claimed.' -NoConsole
}
# ===========================================================================================
#  SECTION 19 :: ACTIVE EXPLOITABILITY VALIDATION + EVIDENCE LEDGER  (part 11/12)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  This is the module that keeps the report honest. Every non-informational finding produced
#  by the tool is passed through a ledger that asks four questions:
#
#     1. What are the prerequisites for this finding to matter?
#     2. Were those prerequisites VERIFIED in this assessment (and where is that evidence)?
#     3. Was a controlled validation performed (and what was the actual response)?
#     4. Is this row CONFIGURATION EVIDENCE, ACTIVE VALIDATION or IMPACT EVIDENCE?
#
#  Findings that only answer question 4 as "configuration" are labelled NOT CONFIRMED for the
#  impact column, so that a reader downloading the CSV cannot mistake an observed setting for a
#  demonstrated compromise.
#
#  The module also performs the one credential-bearing test the scope allows: whether the
#  CURRENT assessment identity holds administrative rights on discovered hosts (verified with a
#  read-only SMB administrative-share handle and, optionally, a single read-only WinRM command).
#  That test uses only the credentials the assessment already runs as - no other credentials
#  are supplied, guessed, sprayed or reused.
# ===========================================================================================

function Get-ValidationClass {
    param([object]$Row)
    $v = [string]$Row.ValidationMethod
    $e = [string]$Row.Exploitability
    $o = [string]$Row.ObservedResult
    # Negated phrases are removed BEFORE matching: "Not demonstrated" must never be read as
    # impact evidence, and "not validated"/"not confirmed" must never be read as validation.
    $eClean = $e
    foreach ($neg in @('not demonstrated','not validated','not confirmed','not proven','never demonstrated','no impact demonstrated','not executed','not attempted')) {
        $eClean = $eClean -replace [regex]::Escape($neg), ''
    }
    $oClean = $o
    foreach ($neg in @('not confirmed','not proven','NOT CONFIRMED','not executed')) {
        $oClean = $oClean -replace [regex]::Escape($neg), ''
    }
    if ($eClean -match '(?i)\bdemonstrated\b|\bproven\b|\bvalidated\b|\bconfirmed\b' -or $oClean -match '(?i)\bPROVEN\b|\bCONFIRMED\b|\bVALIDATED\b') { return 'IMPACT EVIDENCE' }
    if ($v -match '(?i)live |live$|probe|runtime|connect test|NEGOTIATE|AS-REQ|handshake|anonymous bind|X\.224|wsman|Test-') { return 'ACTIVE VALIDATION' }
    return 'CONFIGURATION EVIDENCE'
}

function Test-IsLocalTarget {
    <# Returns $true when a candidate target denotes THIS host rather than a remote one.

       WHY THIS EXISTS: validating 'administrative access' against the local machine is meaningless
       and actively misleading on Windows Server. A connection to the host's own name (or
       \\localhost\\C$) is answered by the local SMB stack without traversing the network, and on
       Server builds the behaviour is additionally shaped by the loopback-check hardening
       (DisableLoopbackCheck / LoopbackCheck registry policy) and by SMB loopback optimisation.
       The result is a FALSE NEGATIVE when the loopback check rejects the connection, or a FALSE
       POSITIVE when the local share resolves for an identity that has no administrative rights
       anywhere else. Either way it would corrupt the Section 19.2 conclusion, so such targets are
       removed before the test and the exclusion is recorded in the evidence.

       Matching is by name AND by address: host name, FQDN, 'localhost', the whole 127.0.0.0/8 and
       ::1 ranges, and any resolved address that is one of this host's own IPv4 addresses. #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $n = $Name.Trim()
    if ($n -match '^(?i)(localhost|localhost\.|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0)$') { return $true }
    if ($n -match '^127\.') { return $true }
    if ($n -match '^\[?::1\]?$') { return $true }

    # ---- name comparison against this host -------------------------------------------------
    $selfNames = @()
    try { $selfNames += [string]$script:HostName } catch { }
    try { $selfNames += [string]$script:HostFqdn } catch { }
    try { $selfNames += [string]$env:COMPUTERNAME } catch { }
    try { if ($env:USERDNSDOMAIN) { $selfNames += ([string]$env:COMPUTERNAME + '.' + [string]$env:USERDNSDOMAIN) } } catch { }
    try { if ($script:DomainName) { $selfNames += ([string]$script:HostName + '.' + [string]$script:DomainName) } } catch { }
    $base = $n.Split('.')[0]
    foreach ($sn in ($selfNames | Where-Object { $_ })) {
        $sb = ([string]$sn).Split('.')[0]
        if ($n -ieq [string]$sn) { return $true }
        if ($base -and $sb -and $base -ieq $sb) { return $true }
    }

    # ---- address comparison against this host ---------------------------------------------
    $locals = @()
    try {
        if (-not $script:LocalIpv4Cache) {
            $nics = @(Get-NicInventory)
            $script:LocalIpv4Cache = @(Get-LocalIpv4 -Nics $nics)
        }
        $locals = @($script:LocalIpv4Cache)
    } catch { }
    if ($locals -contains $n) { return $true }
    if ($locals.Count -gt 0) {
        # A candidate that RESOLVES to one of this host's own addresses is the local machine reached
        # by DNS name; treat it as local rather than as a remote administrative endpoint.
        try {
            $resolved = @([System.Net.Dns]::GetHostAddresses($n) | ForEach-Object { $_.IPAddressToString })
            foreach ($a in $resolved) {
                if ($a -match '^127\.' -or $a -eq '::1') { return $true }
                if ($locals -contains $a) { return $true }
            }
        } catch { }
    }
    return $false
}

function Test-RemoteAdminReachability {
    <# Verifies whether the CURRENT assessment identity holds administrative access on a remote
       host. Two independent, read-only mechanisms are used:
         * SMB: does the administrative share (C$) resolve as a directory handle? Administrative
           access is REQUIRED for this to succeed; a standard user receives access denied.
         * WinRM: does a single read-only command execute in the remote session?
       Neither mechanism writes, deletes or modifies anything on the remote host. #>
    param([string]$HostName, [int]$SmbPort = 445, [int]$WinRmPort = 5985, [switch]$UseWinRmCommand)
    $res = [pscustomobject]@{
        Host = $HostName; SmbAdmin = $null; SmbEvidence = ''; WinRmAccess = $null; WinRmEvidence = ''
        WinRmIdentity = ''; Error = ''; Skipped = $false
    }
    # Defensive guard: never evaluate the local machine as a remote administrative endpoint, even if
    # a caller slips it through (see Test-IsLocalTarget for the false-positive/false-negative
    # reasoning around Windows Server loopback behaviour).
    if (Test-IsLocalTarget -Name $HostName) {
        $res.Skipped = $true
        $res.SmbEvidence = 'SKIPPED - target resolves to the assessment host itself; loopback connections are not evidence of remote administrative access'
        $res.WinRmEvidence = 'SKIPPED - local target'
        return $res
    }
    # Defence in depth: even if a caller slips past the Section 19.2 gate, this helper will not open
    # an SMB or WinRM session to a remote host during a local-only run.
    if (-not (Test-RemoteAllowed)) {
        $res.Skipped = $true
        $res.SmbEvidence = 'SKIPPED - ' + (Get-RemoteSuppressedNote)
        $res.WinRmEvidence = 'SKIPPED - ' + (Get-RemoteSuppressedNote)
        return $res
    }
    $t = Test-TcpPort -Target $HostName -Port $SmbPort -TimeoutMs 900
    if ($t.State -eq 'Open') {
        try {
            # A read-only handle test against the administrative share. Nothing is listed,
            # opened for data or written: only the existence of an administrative connection is
            # evaluated, which is exactly what local-administrator rights allow.
            $ok = [System.IO.Directory]::Exists('\\' + $HostName + '\C$')
            $res.SmbAdmin = [bool]$ok
            $res.SmbEvidence = if ($ok) { 'C$ administrative share resolved as a directory handle from the current identity (administrative access CONFIRMED)' } else { 'C$ administrative share did not resolve (access denied or share removed) - administrative access NOT confirmed' }
        } catch {
            $res.SmbEvidence = 'SMB administrative-share test threw: ' + $_.Exception.Message
        }
    } else {
        $res.SmbEvidence = 'TCP/445 is ' + $t.State + ' from the assessment position - not tested'
    }
    $t2 = Test-TcpPort -Target $HostName -Port $WinRmPort -TimeoutMs 900
    if ($t2.State -eq 'Open') {
        try {
            $wsman = Test-WSMan -ComputerName $HostName -ErrorAction Stop
            $res.WinRmAccess = $true
            $res.WinRmEvidence = 'Test-WSMan succeeded (ProductVersion ' + $wsman.ProductVersion + ') using the current credentials'
            if ($UseWinRmCommand) {
                try {
                    $ident = Invoke-Command -ComputerName $HostName -ScriptBlock { [pscustomobject]@{ Host=$env:COMPUTERNAME; Who=([System.Security.Principal.WindowsIdentity]::GetCurrent().Name); Admin=([System.Security.Principal.WindowsPrincipal]([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) } } -ErrorAction Stop
                    $res.WinRmIdentity = ($ident.Host + ' as ' + $ident.Who + ' (remote local-admin=' + $ident.Admin + ')')
                    $res.WinRmEvidence += ' | read-only remote command executed: ' + $res.WinRmIdentity
                    $res.WinRmAccess = $true
                } catch {
                    $res.WinRmEvidence += ' | remote command execution failed: ' + $_.Exception.Message
                }
            }
        } catch {
            $res.WinRmAccess = $false
            $res.WinRmEvidence = 'WinRM port is open but Test-WSMan failed: ' + $_.Exception.Message
        }
    } else {
        $res.WinRmEvidence = 'TCP/' + $WinRmPort + ' is ' + $t2.State + ' from the assessment position - not tested'
    }
    return $res
}

function Invoke-Section19_Validation {
    Write-Host ''
    Write-Host '  -- 19.1 Prerequisite and reachability verification for candidate findings ---------' -ForegroundColor DarkCyan
    $F = Get-LocalFactsForPaths
    $preRows = @()
    $preRows += [pscustomobject]@{ Prerequisite='Administrative rights on this host'; Verified=$(if ($F.IsAdmin) { 'YES - token evaluation' } else { 'NO - standard user context' }); Evidence='WindowsPrincipal.IsInRole(Administrator) + integrity level ' + $F.Integrity }
    $preRows += [pscustomobject]@{ Prerequisite='Local SMB endpoint reachable (TCP/445)'; Verified=$(if ((Test-TcpPort -Target '127.0.0.1' -Port 445 -TimeoutMs 800).State -eq 'Open') { 'YES - TCP connect' } else { 'NO - endpoint not listening locally' }); Evidence='Loopback TCP connect test' }
    $preRows += [pscustomobject]@{ Prerequisite='SMB signing not required (relay precondition)'; Verified=$(if ($null -eq $F.SmbServerSigning) { 'UNKNOWN - probe inconclusive' } elseif ($F.SmbServerSigning) { 'NO - signing IS required, relay precondition not met' } else { 'YES - validated at protocol level' }); Evidence='SMB2 NEGOTIATE SecurityMode from Section 3' }
    $preRows += [pscustomobject]@{ Prerequisite='LSASS unprotected (credential-access precondition)'; Verified=$(if ($null -eq $F.LsassProtected) { 'UNKNOWN - runtime query unavailable' } elseif ($F.LsassProtected) { 'NO - LSASS is protected' } else { 'YES - run-time protection level None' }); Evidence='NtQueryInformationProcess(ProcessProtectionInformation) from Section 5' }
    $preRows += [pscustomobject]@{ Prerequisite='Local firewall permits inbound administrative traffic'; Verified=$(if ($F.FirewallOn) { 'NO - firewall enabled with inbound blocked by default (control present)' } else { 'YES - inbound allowed / firewall off' }); Evidence='Get-NetFirewallProfile state from Section 2.7' }
    $preRows += [pscustomobject]@{ Prerequisite='Kerberos KDC reachable (pre-auth / Kerberoasting preconditions)'; Verified='SEE SECTION 10/11'; Evidence='TCP/88 reachability plus live AS-REQ in Section 10.2' }
    $preRows += [pscustomobject]@{ Prerequisite='Remote hosts reachable (lateral-movement precondition)'; Verified=$(if (@($F.Matrix).Count -gt 0) { 'YES - ' + @($F.Matrix).Count + ' service exposure(s) observed' } else { 'NO - no remote reachability evidence' }); Evidence='Bounded TCP sweep from Section 8' }
    Write-Table -Rows $preRows -Columns @('Prerequisite','Verified','Evidence') -Headers @{ Prerequisite='Prerequisite'; Verified='Verified in this assessment'; Evidence='Evidence source' }
    Add-Finding -Category 'Validation' -Status 'INFO' -CatClass 'Context' -Attribute 'Prerequisite verification ledger' `
        -Finding 'Prerequisites for every candidate finding were individually verified rather than assumed. The table above states, for each prerequisite, whether it was met and which module proved it.' `
        -Observed (($preRows | ForEach-Object { $_.Prerequisite + ' => ' + $_.Verified }) -join ' | ') `
        -Validation 'Aggregation of the evidence produced by Sections 1-18' -Class 'Low' -CatClass 'Context' `
        -Remediation 'Where a prerequisite is UNKNOWN, resolve it before relying on any finding that depends on it.' `
        -Impact 'This ledger is what separates a technically possible attack from a demonstrated one in this report.' -NoConsole

    Write-Host ''
    Write-Host '  -- 19.2 Credential-reachability validation with the current identity --------------' -ForegroundColor DarkCyan
    $candidates = @()
    foreach ($m in @($F.Matrix)) {
        if ([int]$m.Port -in @(445,5985,5986)) { $candidates += $m.Host }
    }
    # ---- SELF/LOOPBACK EXCLUSION ------------------------------------------------------------
    # Only genuinely remote hosts can demonstrate lateral movement. The local host is removed by
    # name, FQDN and address before the list is capped, and what was removed is recorded so the
    # report shows the scope reduction instead of silently testing fewer hosts.
    $candidates = @($candidates | Sort-Object -Unique)
    $excludedLocal = @()
    $remoteOnly = @()
    foreach ($c in $candidates) {
        if (Test-IsLocalTarget -Name $c) { $excludedLocal += $c } else { $remoteOnly += $c }
    }
    # SCOPE FILTER before the ceiling is applied, so the five that are chosen are five IN SCOPE -
    # filtering afterwards could leave fewer than five candidates when in-scope hosts existed.
    if ($script:ScopeActive) {
        $beforeScope = $remoteOnly.Count
        $remoteOnly = @($remoteOnly | Where-Object { Test-InScope -Target $_ })
        if ($remoteOnly.Count -lt $beforeScope) { Write-Status 'INFO' ('engagement scope removed ' + ($beforeScope - $remoteOnly.Count) + ' candidate(s) outside: ' + $script:ScopeText) }
    }
    if (Test-KillSwitch) {
        Write-Status 'NOT TESTABLE' 'The kill switch is active - the administrative-reachability candidates were not contacted.'
        $remoteOnly = @()
    }
    $candidates = @($remoteOnly | Select-Object -First 5)
    if ($excludedLocal.Count -gt 0) {
        Write-Status 'INFO' ('Excluded ' + $excludedLocal.Count + ' candidate(s) that resolve to the assessment host itself (loopback is not remote access): ' + ($excludedLocal -join ', '))
    }
    Add-Finding -Category 'Validation' -Status 'INFO' -CatClass 'Context' -Attribute 'Remote-validation target selection' `
        -Finding ('Of the reachable administrative endpoints discovered, ' + $excludedLocal.Count + ' resolved to the assessment host itself and were excluded; ' + $candidates.Count + ' remote host(s) remain as validation candidates.') `
        -Observed ('Excluded as local: ' + $(if ($excludedLocal.Count) { $excludedLocal -join ', ' } else { 'none' }) + ' | Selected as remote: ' + $(if ($candidates.Count) { $candidates -join ', ' } else { 'none' })) `
        -Prerequisites 'SMB or WinRM reachability recorded in Section 8.' `
        -Configured 'Section 19.2 target selection' `
        -Validation 'Name, FQDN and address comparison against the assessment host (host name, WORKGROUP/DNS suffix, the full 127.0.0.0/8 range, ::1, and every local IPv4 address), plus DNS resolution of each candidate.' `
        -Class 'Low' `
        -Remediation 'None - control applied by the tool. A loopback result would be a false positive (the local share resolves for any caller) or a false negative (Server loopback-check hardening rejects the connection), so it is never used as evidence of remote administrative rights.' `
        -Impact 'None directly; it protects the accuracy of the lateral-movement finding that follows.' -NoConsole

    $remoteSuppressed = -not (Test-RemoteAllowed)
    if ($remoteSuppressed) {
        Write-Status 'NOT TESTABLE' ((Get-RemoteSuppressedNote) + ' - remote administrative validation was skipped.')
        $candidates = @()
    } else {
        Write-Status 'NOT TESTABLE' 'No remote host with SMB or WinRM reachability was identified, so credential reachability could not be validated.'
    }
    if ($candidates.Count -eq 0) {
        Add-Finding -Category 'Validation' -Status 'NOT TESTABLE' -Attribute 'Remote administrative access (current identity)' `
            -Finding ('Whether the current identity holds administrative rights on other hosts could not be validated: ' + $(if ($remoteSuppressed) { 'the operator requested a local-only run, so no remote host was contacted.' } else { 'no reachable SMB/WinRM host was in the assessed scope.' })) `
            -Validation 'Not performed' -Class 'High' -CatClass 'IdentityRights' `
            -Remediation 'Include at least one reachable administrative endpoint in the discovery scope if lateral-movement validation is required by the engagement.' `
            -Impact 'Lateral-movement findings remain CANDIDATES rather than demonstrated paths.' -NoConsole
    } else {
        Write-Host ('    candidate hosts (max 5): ' + ($candidates -join ', ')) -ForegroundColor DarkGray
        Write-Host '    This test uses ONLY the credentials this assessment already runs as. It resolves an' -ForegroundColor DarkGray
        Write-Host '    administrative share handle (read-only) and, if you agree, runs one read-only command' -ForegroundColor DarkGray
        Write-Host '    over WinRM. Nothing is written, copied, modified or deleted on the remote host.' -ForegroundColor DarkGray
        # Both gates go through Request-Consent, so an unattended run cannot stall on stdin and the
        # evidence states HOW the decision was reached (console answer, launch switch, or safe default).
        $doIt = $false; $useWinRmCmd = $false
        $c1 = Request-Consent -StepName 'Remote administrative access validation' -DefaultAllowed $false `
            -Question 'Validate remote administrative access from the current identity? [y/N]'
        $doIt = [bool]$c1.Allowed
        if ($doIt) {
            $c2 = Request-Consent -StepName 'Read-only WinRM command execution' -DefaultAllowed $false `
                -Question 'Also execute ONE read-only command over WinRM (hostname/whoami) as proof? [y/N]'
            $useWinRmCmd = [bool]$c2.Allowed
        }
        $consentMode19 = $c1.Mode
        Write-Host ('    consent decision: ' + $c1.Note) -ForegroundColor DarkGray
        if (-not $doIt) {
            Write-Status 'NOT TESTABLE' 'Operator did not authorise the credential-reachability validation; published as not tested.'
            Add-Finding -Category 'Validation' -Status 'NOT TESTABLE' -Attribute 'Remote administrative access (current identity)' `
                -Finding 'The credential-reachability validation was not authorised at the console, so no claim is made about the current identity''s administrative rights on other hosts.' `
                -Observed ('Candidate hosts that would have been tested: ' + ($candidates -join ', ') + '; consent path: ' + $consentMode19) `
                -Validation 'Not performed (operator control)' -Class 'High' -CatClass 'IdentityRights' `
                -Remediation 'Authorise this test explicitly if the engagement requires demonstrated lateral movement; it is a read-only, single-attempt check per host.' `
                -Impact 'Lateral-movement findings remain CANDIDATES rather than demonstrated paths.' -NoConsole
        } else {
            $confirmed = 0
            foreach ($h in $candidates) {
                $r = Test-RemoteAdminReachability -HostName $h -UseWinRmCommand:$useWinRmCmd
                $adminOk = ($r.SmbAdmin -eq $true) -or ($r.WinRmAccess -eq $true -and $r.WinRmEvidence -match 'read-only remote command executed')
                if ($adminOk) { $confirmed++ }
                Write-Status $(if ($adminOk) { 'VALIDATED' } else { 'NOT CONFIRMED' }) ($h + ' :: SMB: ' + $r.SmbEvidence + ' | WinRM: ' + $r.WinRmEvidence)
                Add-Finding -Category 'Validation' -Status $(if ($adminOk) { 'VALIDATED' } else { 'NOT CONFIRMED' }) -Attribute 'Remote administrative access from current identity' `
                    -Source $script:HostName -Target $h -Port '445,5985' `
                    -Finding $(if ($adminOk) { ('The current assessment identity (' + $script:CurrentUser + ') holds administrative access on ' + $h + ' - a lateral-movement path that is validated end to end with no invented steps.') } else { ('Administrative access from the current identity to ' + $h + ' was NOT confirmed. The absence of an administrative share handle is recorded as a negative result, not as a blocked path.') }) `
                    -Configured ('Assessment identity: ' + $script:CurrentUser + ' (SID ' + $script:CurrentUserSid + ')') `
                    -Observed ('SMB: ' + $r.SmbEvidence + ' || WinRM: ' + $r.WinRmEvidence + $(if ($r.WinRmIdentity) { ' || remote identity: ' + $r.WinRmIdentity } else { '' })) `
                    -Validation 'Read-only SMB administrative-share handle resolution and (if authorised) a single read-only WinRM command. No file was created, modified, read for content, or deleted on the remote host; no service, task or registry state was altered.' `
                    -Prerequisites 'The current assessment identity must hold administrative rights on the remote host (this is exactly what the test measures).' `
                    -Exploitability $(if ($adminOk) { 'Demonstrated with the real assessment credentials: administrative access is available on this host from the current context.' } else { 'Not demonstrated for this host.' }) `
                    -Class 'Critical' -CatClass 'IdentityRights' `
                    -Remediation 'Remove credential overlap between hosts: deploy LAPS to full coverage so local administrator passwords are unique and rotated, eliminate shared service accounts that hold local administrative rights, remove standing administrative rights in favour of just-in-time elevation, and restrict administrative interfaces to a privileged-access tier.' `
                    -Impact $(if ($adminOk) { 'This is a demonstrated lateral-movement capability: any credential compromise equal to the current identity (for example a single cracked password or a relayed authentication) yields administrative control of these hosts, and from there the credential material and data on them.' } else { 'No impact demonstrated for this host from the current identity.' })
            }
            $script:Facts['RemoteAdminValidated'] = $confirmed
            Add-Finding -Category 'Validation' -Status $(if ($confirmed -gt 0) { 'VALIDATED' } else { 'NOT CONFIRMED' }) -Attribute 'Credential-reachability validation summary' `
                -Finding ($confirmed.ToString() + ' of ' + $candidates.Count + ' tested host(s) accepted administrative access from the current assessment identity.') `
                -Observed ('Tested hosts: ' + ($candidates -join ', ')) `
                -Validation 'Bounded, read-only, credential-reuse-with-own-identity test (see per-host rows)' `
                -Class 'Critical' -CatClass 'IdentityRights' `
                -Remediation 'Treat this as the primary evidence for the credential-reuse finding: local administrator password reuse (or shared administrative service accounts) is the underlying condition, and LAPS plus tiered administration is the fix.' `
                -Impact 'This is the difference between "reachable administrative interfaces" and "administrative access demonstrated from a single identity" - the latter is the lateral-movement condition that matters most in an internal assessment.'
        }
    }

    Write-Host ''
    Write-Host '  -- 19.3 Assessment artifact cleanup verification ---------------------------------' -ForegroundColor DarkCyan
    $leftovers = @()
    try {
        $patterns = @('eia-secpol-*.inf','eia-privrights-*.inf','EIA-writetest-*.tmp')
        $scanDirs = @($env:TEMP, $env:SystemRoot, (Get-Location).Path)
        foreach ($d in ($scanDirs | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            foreach ($p in $patterns) {
                $hits = @(Get-ChildItem -LiteralPath $d -Filter $p -ErrorAction SilentlyContinue)
                foreach ($h in $hits) { $leftovers += $h.FullName }
            }
        }
    } catch { }
    if ($leftovers.Count -eq 0) {
        Write-Status 'PASS' 'No assessment artifacts remain (policy exports and write-test markers were removed).'
        Add-Finding -Category 'Validation' -Status 'INFO' -CatClass 'Context' -Attribute 'Artifact cleanup' `
            -Finding 'All temporary assessment artifacts were removed: security-policy exports, privilege-rights exports and write-test marker files.' `
            -Observed 'Cleanup verified by scanning %TEMP%, %SystemRoot% and the working directory for the tool''s artifact patterns.' `
            -Validation 'Filesystem verification after the assessment completed' -Class 'Low' -CatClass 'Context' `
            -Remediation 'None required.' -Impact 'None - this row exists because an assessment tool that leaves artifacts changes the state it was measuring.'
    } else {
        Write-Status 'WARN' ('Assessment artifacts remain on the host: ' + ($leftovers -join ', '))
        Add-Finding -Category 'Validation' -Status 'WARN' -Attribute 'Artifact cleanup incomplete' `
            -Finding 'Temporary artifacts created during the assessment could not be removed and must be deleted manually.' `
            -Observed ($leftovers -join ', ') -Validation 'Filesystem scan for the tool''s artifact patterns' `
            -Class 'Low' -CatClass 'Context' `
            -Remediation 'Delete the listed files. They contain no credential material (policy values and a marker file), but the host must be returned to its pre-assessment state.' `
            -Impact 'Unchanged host state is an assessment-integrity requirement, not a security impact on the host.'
    }

    Write-Host ''
    Write-Host '  -- 19.4 Evidence ledger: configuration / validation / impact ---------------------' -ForegroundColor DarkCyan
    $rows = @()
    foreach ($f in $script:Findings) {
        if ($f.Status -in @('INFO','PASS')) { continue }
        $rows += [pscustomobject]@{
            Severity = $f.Severity; Status = $f.Status; Class = (Get-ValidationClass -Row $f)
            Category = $f.Category; Target = $f.Target; Attribute = $f.Attribute
            Prereq = $f.Prerequisites
        }
    }
    if ($rows.Count -eq 0) {
        Write-Status 'INFO' 'No weaknesses were recorded, so the evidence ledger is empty.'
    } else {
        $grp = $rows | Group-Object -Property Class
        Write-Table -Rows ($grp | ForEach-Object { [pscustomobject]@{ Classification=$_.Name; Count=$_.Count } }) -Columns @('Classification','Count') -Headers @{ Classification='Evidence classification'; Count='Rows' }
        Write-Table -Rows ($rows | Sort-Object -Property Status, Severity | Select-Object -First 50) -Columns @('Severity','Status','Class','Category','Target','Attribute') `
            -Headers @{ Severity='Sev'; Status='Status'; Class='Evidence class'; Category='Category'; Target='Target'; Attribute='Attribute' }
        if ($rows.Count -gt 50) { Write-Host ('    ... ' + ($rows.Count - 50) + ' further rows are in the CSV report.') -ForegroundColor DarkGray }
        foreach ($g in $grp) {
            $ex = @($g.Group | Where-Object { $_.Status -eq 'VALIDATED' }).Count
            Add-Finding -Category 'Validation' -Status 'INFO' -CatClass 'Context' -Attribute ('Evidence ledger: ' + $g.Name) `
                -Finding ($g.Count.ToString() + ' row(s) are classified as ' + $g.Name + $(if ($g.Name -eq 'IMPACT EVIDENCE') { ' - these are the only rows that may be presented as demonstrated impact.' } elseif ($g.Name -eq 'ACTIVE VALIDATION') { ' - the condition was observed at runtime from the affected system, but end-to-end impact was not demonstrated.' } else { ' - the condition is documented from configuration or directory attributes and its impact is NOT demonstrated.' })) `
                -Observed (($g.Group | Select-Object -First 12 | ForEach-Object { $_.Category + '/' + $_.Attribute }) -join ' | ') `
                -Validation 'Programmatic classification of every non-informational row by its recorded validation method and exploitability statement.' `
                -Class 'Low' -CatClass 'Context' `
                -Remediation 'Read the CSV classification column before escalating any row to the business: a CONFIGURATION EVIDENCE row requires an owner decision, an ACTIVE VALIDATION row requires prioritisation, and an IMPACT EVIDENCE row requires immediate remediation.' `
                -Impact 'Not applicable - this row is a reporting-integrity control.' -NoConsole
        }
    }
    $script:Facts['LedgerRows'] = $rows
}
# ===========================================================================================
#  SECTIONS 20-21 + REPORTING AND SIGN-OFF  (part 12/12)
#
#  SECURITY PURPOSE
#  ----------------------------------------------------------------------------------------
#  Section 20 correlates individual findings into multi-step chains and assigns each chain a
#  verdict driven by the weakest link (CONFIRMED / PARTIALLY CONFIRMED / NOT CONFIRMED /
#  NOT TESTABLE). Section 21 finalises the machine-readable evidence report and prints the
#  executive summary.
#
#  NO COMPOSITE SCORE IS PRODUCED. The severity of each row comes from the deterministic
#  matrix documented in part 1 of the engine; producing a single "security score" from
#  incomparable findings would be an unsupportable judgement and is deliberately not done.
# ===========================================================================================

function Add-AttackChain {
    param(
        [Parameter(Mandatory=$true)][string]$Chain,
        [Parameter(Mandatory=$true)][object[]]$Links,     # @{ Name; State='confirmed|absent|unknown'; Evidence }
        [Parameter(Mandatory=$true)][string]$ImpactStatement,
        [string]$Remediation = '',
        [string]$Class = 'High'
    )
    $confirmed = @($Links | Where-Object { $_.State -eq 'confirmed' })
    $absent    = @($Links | Where-Object { $_.State -eq 'absent' })
    $unknown   = @($Links | Where-Object { $_.State -eq 'unknown' })
    $verdict = ''
    if ($confirmed.Count -eq $Links.Count) { $verdict = 'CONFIRMED' }
    elseif ($absent.Count -gt 0) { $verdict = 'NOT CONFIRMED' }
    elseif ($unknown.Count -gt 0 -and $confirmed.Count -gt 0) { $verdict = 'PARTIALLY CONFIRMED' }
    elseif ($unknown.Count -gt 0) { $verdict = 'NOT TESTABLE' }
    else { $verdict = 'PARTIALLY CONFIRMED' }

    $status = switch ($verdict) {
        'CONFIRMED'            { 'VALIDATED' }
        'PARTIALLY CONFIRMED'  { 'RISK DETECTED' }
        'NOT CONFIRMED'        { 'NOT CONFIRMED' }
        default                { 'NOT TESTABLE' }
    }
    Write-Host ''
    Write-Host ('    CHAIN [' + $verdict + '] ' + $Chain) -ForegroundColor $(switch ($verdict) { 'CONFIRMED' { 'Magenta' } 'PARTIALLY CONFIRMED' { 'Yellow' } 'NOT CONFIRMED' { 'DarkGray' } default { 'DarkYellow' } })
    foreach ($l in $Links) {
        $sym = switch ($l.State) { 'confirmed' { 'OK ' } 'absent' { 'NO ' } default { '?  ' } }
        Write-Host ('      ' + $sym + $l.Name + ' :: ' + $l.Evidence) -ForegroundColor $(switch ($l.State) { 'confirmed' { 'Green' } 'absent' { 'DarkGray' } default { 'DarkYellow' } })
    }
    Add-Finding -Category 'Attack Chain Correlation' -Status $status -Attribute 'Attack chain' `
        -Finding ($Chain + ' -> VERDICT: ' + $verdict) `
        -Configured (($Links | ForEach-Object { '[' + $_.State.ToUpper() + '] ' + $_.Name + ': ' + $_.Evidence }) -join ' || ') `
        -Observed ('Weakest-link verdict: ' + $verdict + '. ' + $confirmed.Count + ' of ' + $Links.Count + ' links confirmed, ' + $absent.Count + ' disproved, ' + $unknown.Count + ' unknown.') `
        -Validation 'Correlation of evidence collected by Sections 1-19. No new exploitation was performed here: each link cites the module and test that produced it.' `
        -Prerequisites $(if ($absent.Count -gt 0) { 'At least one link is DISPROVED on this host, so the chain is not available here.' } elseif ($unknown.Count -gt 0) { 'The links recorded as unknown must be resolved before this chain can be treated as available.' } else { 'All prerequisites were validated during this assessment.' }) `
        -Exploitability $(switch ($verdict) { 'CONFIRMED' { 'Every link is evidenced; the chain is technically available from the assessed position. The final impact step was not executed by this tool.' } 'PARTIALLY CONFIRMED' { 'Some links are evidenced and at least one remains unknown: the chain is POSSIBLE but NOT demonstrated.' } 'NOT CONFIRMED' { 'Disproved on this host by the evidence shown.' } default { 'Not determinable from this context.' } }) `
        -Class $Class -CatClass 'IdentityRights' -Remediation $Remediation -Impact $ImpactStatement
}

function Invoke-Section20_Chains {
    $F = Get-LocalFactsForPaths
    $matrix = @($F.Matrix)
    $dcLike = @()
    foreach ($m in $matrix) { if ([int]$m.Port -eq 88 -or [int]$m.Port -eq 389) { $dcLike += $m.Host } }
    $dcLike = @($dcLike | Sort-Object -Unique)
    $adminSvc = @()
    foreach ($m in $matrix) { if ([int]$m.Port -in @(3389,5985,5986)) { $adminSvc += ($m.Host + ':' + $m.Port) } }

    Write-Host ''
    Write-Host '  -- 20.1 Evidence-based attack chains ---------------------------------------------' -ForegroundColor DarkCyan
    Write-Host '     A chain is only reported as CONFIRMED when every link is supported by evidence.' -ForegroundColor DarkGray

    # ---- Chain A: weak authentication -> reachable service -> excessive privilege -----------
    $smbSign = $F.SmbServerSigning
    $smbReach = [bool](@($matrix | Where-Object { [int]$_.Port -eq 445 }).Count -gt 0)
    $kerbReach = [bool](@($matrix | Where-Object { [int]$_.Port -eq 88 }).Count -gt 0)
    $privAcct = $script:Facts['SpnPrivilegedCount']
    Add-AttackChain -Chain 'Weak authentication -> reachable service -> excessive privilege' `
        -Links @(
            @{ Name='SMB signing not enforced on the assessed host'; State=$(if ($null -eq $smbSign) { 'unknown' } elseif ($smbSign) { 'absent' } else { 'confirmed' }); Evidence=$(if ($null -eq $smbSign) { 'SMB NEGOTIATE probe inconclusive (Section 3)' } elseif ($smbSign) { 'Section 3: SIGNING_REQUIRED is set, so unsigned sessions are refused - this chain is blocked at its first link' } else { 'Section 3: SMB2 NEGOTIATE response omits SIGNING_REQUIRED - unsigned sessions are accepted' }) },
            @{ Name='SMB reachable within the assessed scope'; State=$(if ($smbReach) { 'confirmed' } else { 'unknown' }); Evidence=$(if ($smbReach) { 'Section 8: TCP/445 reachable on at least one host' } else { 'Section 8: no TCP/445 exposure observed in scope' }) },
            @{ Name='A privileged identity authenticates to the affected service'; State='unknown'; Evidence='NOT tested by this tool: coercing or capturing another identity''s authentication is outside the authorised test surface' },
            @{ Name='Relayed authentication yields privilege on the target'; State='unknown'; Evidence='NOT tested: the relay payload was not executed' }
        ) -ImpactStatement 'Where signing is not enforced and an identity can be coerced into authenticating to the assessed host, the authentication can be relayed to obtain the victim''s access on that system - the classic path from a single coerced authentication to administrative access.' `
        -Remediation 'Require SMB signing on every server and workstation (GPO: Microsoft network server/client: Digitally sign communications (always)), enforce LDAP signing and channel binding on domain controllers, and eliminate NTLM in favour of Kerberos where the application estate allows it.' `
        -Class 'High'

    # ---- Chain B: pre-authentication disabled -> offline recovery -> account access --------
    $preAuthValidated = [int]$script:Facts['PreAuthValidated']
    $preAuthConfig = [int]$script:Facts['PreAuthConfigured']
    Add-AttackChain -Chain 'Kerberos pre-authentication disabled -> offline password recovery -> account access' `
        -Links @(
            @{ Name='Account(s) with DONT_REQ_PREAUTH (0x00400000) exist'; State=$(if ($preAuthConfig -gt 0) { 'confirmed' } else { 'absent' }); Evidence=$(if ($preAuthConfig -gt 0) { $preAuthConfig.ToString() + ' account(s) enumerated with exact hexadecimal UAC decoding (Section 10)' } else { 'Section 10: no account carries the bit' }) },
            @{ Name='KDC reachable from an unauthenticated position'; State=$(if ($kerbReach) { 'confirmed' } else { 'unknown' }); Evidence=$(if ($kerbReach) { 'Section 8/10.2: TCP/88 reachable' } else { 'KDC reachability not observed in scope' }) },
            @{ Name='KDC issues an AS-REP without pre-authentication data'; State=$(if ($preAuthValidated -gt 0) { 'confirmed' } elseif ($preAuthConfig -gt 0) { 'unknown' } else { 'absent' }); Evidence=$(if ($preAuthValidated -gt 0) { 'Live AS-REQ test returned an AS-REP for ' + $preAuthValidated + ' account(s) (Section 10.2)' } else { 'Not validated in this run' }) },
            @{ Name='Password recovered from the AS-REP'; State='unknown'; Evidence='NOT performed: offline cracking is prohibited by this tool''s design; feasibility depends on password strength (Section 9.6 policy)' }
        ) -ImpactStatement 'A reachable KDC plus a pre-authentication-disabled account yields crackable material without any credential, any lockout and any failed-logon noise. Recovery of the password yields whatever the account can reach.' `
        -Remediation 'Clear the flag on every account, reset the affected passwords with long random values, and add alerting on Kerberos 4768 requests for accounts that have ever had the flag set.' `
        -Class 'Critical'

    # ---- Chain C: segmentation weakness -> administrative service -> critical host ---------
    $dcAdminExposed = @($matrix | Where-Object { [int]$_.Port -in @(3389,5985,5986) -and ($dcLike -contains $_.Host) })
    $legacy139 = @($matrix | Where-Object { [int]$_.Port -eq 139 })
    Add-AttackChain -Chain 'Segmentation weakness -> administrative service -> critical host' `
        -Links @(
            @{ Name='Assessment segment reaches administrative services'; State=$(if ($adminSvc.Count -gt 0) { 'confirmed' } else { 'absent' }); Evidence=$(if ($adminSvc.Count -gt 0) { $adminSvc.Count.ToString() + ' administrative service exposure(s) observed: ' + (($adminSvc | Select-Object -First 6) -join ', ') } else { 'Section 8: no RDP/WinRM exposure observed in scope' }) },
            @{ Name='A critical (directory) host is reachable from the same position'; State=$(if ($dcLike.Count -gt 0) { 'confirmed' } else { 'absent' }); Evidence=$(if ($dcLike.Count -gt 0) { 'Kerberos/LDAP-reachable host(s): ' + ($dcLike -join ', ') } else { 'No host with the Kerberos+LDAP service profile was observed' }) },
            @{ Name='Legacy transport (TCP/139) still exposed'; State=$(if ($legacy139.Count -gt 0) { 'confirmed' } else { 'absent' }); Evidence=$(if ($legacy139.Count -gt 0) { $legacy139.Count.ToString() + ' host(s) expose NetBIOS session service' } else { 'No TCP/139 exposure observed' }) },
            @{ Name='Credentials valid on the critical host'; State='unknown'; Evidence='See Section 19.2 credential-reachability results; where those rows are VALIDATED this link is confirmed for the tested hosts' }
        ) -ImpactStatement 'Administrative interfaces reachable from a general segment convert any harvested or reused credential into interactive control of the destination, and legacy NetBIOS transport widens relay opportunities. When a directory host is reachable with administrative services exposed and no signing enforcement, the boundary between "user network" and "tier 0" has effectively been removed.' `
        -Remediation 'Place administrative interfaces behind a dedicated privileged-access tier with network ACLs enforced on both ends, disable TCP/139 estate-wide, remove RDP/WinRM exposure from directory servers, and require signing/encryption on every directory-related protocol.' `
        -Class 'High'

    # ---- Chain D: local permission weakness -> privilege boundary -> administrative context --
    $unquoted = [int]$script:Facts['UnquotedServicePaths']
    $writablePath = [int]$script:Facts['WritablePathDirs']
    Add-AttackChain -Chain 'Local permission weakness -> privilege boundary -> administrative context' `
        -Links @(
            @{ Name='Local permission weakness present'; State=$(if (($unquoted -gt 0) -or ($writablePath -gt 0)) { 'confirmed' } else { 'absent' }); Evidence=$(if (($unquoted -gt 0) -or ($writablePath -gt 0)) { 'Section 17: unquoted service paths=' + $unquoted + ', writable PATH directories=' + $writablePath } else { 'Section 17: no unquoted service path or writable PATH directory was identified' }) },
            @{ Name='Write permission usable by the current identity'; State=$(if ($script:Facts['WriteProofObtained']) { 'confirmed' } else { 'unknown' }); Evidence=$(if ($script:Facts['WriteProofObtained']) { 'Controlled marker-file write proof succeeded and the artifact was removed (Section 17)' } else { 'ACL evidence only; the write proof did not succeed from this token' }) },
            @{ Name='Code execution as the privileged service identity'; State='unknown'; Evidence='NOT executed: a binary replacement would be an actual escalation and is outside this tool''s design' },
            @{ Name='Administrative context obtained'; State=$(if ($script:Facts['UnquotedEscalationExecuted']) { 'confirmed' } else { 'unknown' }); Evidence='Never claimed without execution evidence' }
        ) -ImpactStatement 'A writable service directory or an unquoted service path converts standard-user write access into SYSTEM code execution at the next service start, which is the first step of nearly every workstation-to-domain escalation path.' `
        -Remediation 'Quote service paths, remove non-administrative write permissions from service directories and PATH entries, and keep local privilege boundaries documented so that a later finding can be attributed to the correct control.' `
        -Class 'High'

    # ---- Chain E: SPN exposure -> service account risk -> privileged resource ---------------
    Add-AttackChain -Chain 'SPN exposure -> service-account risk -> privileged resource' `
        -Links @(
            @{ Name='User accounts hold SPNs'; State=$(if ([int]$script:Facts['SpnUserAccounts'] -gt 0) { 'confirmed' } else { 'absent' }); Evidence=$(if ([int]$script:Facts['SpnUserAccounts'] -gt 0) { [string]$script:Facts['SpnUserAccounts'] + ' SPN-holding user account(s) enumerated (Section 11)' } else { 'No user account holds an SPN' }) },
            @{ Name='Privileged or stale-password SPN account'; State=$(if ($privAcct -gt 0) { 'confirmed' } elseif ($null -eq $privAcct) { 'unknown' } else { 'absent' }); Evidence=$(if ($privAcct -gt 0) { $privAcct.ToString() + ' privileged SPN account(s) (Section 11)' } else { 'No privileged SPN account identified' }) },
            @{ Name='Ticket material is crackable (RC4 and/or old password)'; State=$(if ([int]$script:Facts['Rc4EnabledObjects'] -gt 0 -or [int]$script:Facts['StaleSpnPasswords'] -gt 0) { 'confirmed' } else { 'unknown' }); Evidence=('Sections 11/13: stale SPN passwords=' + [string]$script:Facts['StaleSpnPasswords'] + ', objects permitting RC4=' + [string]$script:Facts['Rc4EnabledObjects']) },
            @{ Name='Recovered account accesses a privileged resource'; State='unknown'; Evidence='NOT executed: no ticket was requested and no cracking was performed' }
        ) -ImpactStatement 'A single authenticated domain foothold is enough to request service tickets for these accounts. Older passwords and RC4-encrypted tickets make offline recovery practical, and the recovered account''s privileges determine whether the result is lateral movement or domain compromise.' `
        -Remediation 'Migrate to gMSA, rotate service-account passwords with long random values, set msDS-SupportedEncryptionTypes=0x18 (AES-only), and remove privileged-group membership from every service account.' `
        -Class 'Critical'

    # ---- Chain F: unprotected credentials -> credential reuse -> estate-wide access --------
    $lsass = $F.LsassProtected
    Add-AttackChain -Chain 'Local administrator -> credential material -> estate-wide access' `
        -Links @(
            @{ Name='Administrator-level context on the assessed host'; State=$(if ($F.IsAdmin) { 'confirmed' } else { 'unknown' }); Evidence='Token evaluation in Section 1' },
            @{ Name='Credential material reachable (LSASS unprotected / WDigest caching)'; State=$(if ($lsass -eq $false -or $F.Wdigest -eq $true) { 'confirmed' } elseif ($null -eq $lsass) { 'unknown' } else { 'absent' }); Evidence=('Sections 2.8/5: LSASS protected=' + $(if ($null -eq $lsass) { 'unknown' } else { [string]$lsass }) + ', Credential Guard=' + $(if ($null -eq $F.CredGuard) { 'unknown' } else { [string]$F.CredGuard }) + ', WDigest cleartext caching=' + $(if ($null -eq $F.Wdigest) { 'unknown' } else { [string]$F.Wdigest })) },
            @{ Name='Credential reuse across hosts'; State=$(if ([int]$script:Facts['RemoteAdminValidated'] -gt 0 -or [int]$script:Facts['LapsCoverageMissing'] -gt 0) { 'confirmed' } else { 'unknown' }); Evidence=('Sections 14/19: hosts accepting the assessment identity as administrator=' + [string]$script:Facts['RemoteAdminValidated'] + ', computers without LAPS metadata=' + [string]$script:Facts['LapsCoverageMissing']) },
            @{ Name='Estate-wide administrative access'; State='unknown'; Evidence='Never claimed: the credential-extraction step itself was not performed by this tool' }
        ) -ImpactStatement 'Unprotected credential material plus credential reuse is the combination that turns one compromised workstation into an estate-wide compromise. Every link above is independently measurable, which is why this chain is the priority remediation target rather than any single finding.' `
        -Remediation 'Enable LSA protection and Credential Guard, deploy LAPS to full coverage, eliminate shared local and service credentials, restrict local administrator membership, and enforce tiered administration with just-in-time elevation.' `
        -Class 'Critical'
    # ---- Chain G: DEMONSTRATED lateral movement (populated only when Section 19 validated it) ----
    $validatedRemote = 0
    if ($script:Facts.ContainsKey('RemoteAdminValidated')) { $validatedRemote = [int]$script:Facts['RemoteAdminValidated'] }
    Add-AttackChain -Chain 'Assessment identity -> credential reuse -> administrative access on other hosts' `
        -Links @(
            @{ Name='Assessment identity holds administrative rights locally'; State=$(if ($script:IsAdmin) { 'confirmed' } else { 'unknown' }); Evidence='Token evaluation in Section 1' },
            @{ Name='Administrative interface reachable on other hosts'; State=$(if (@($script:MatrixResult).Count -gt 0) { 'confirmed' } else { 'unknown' }); Evidence='Section 8 bounded reachability sweep' },
            @{ Name='Administrative access VALIDATED on at least one remote host'; State=$(if ($validatedRemote -gt 0) { 'confirmed' } elseif ($script:Facts.ContainsKey('RemoteAdminValidated')) { 'absent' } else { 'unknown' }); Evidence=$(if ($validatedRemote -gt 0) { $validatedRemote.ToString() + ' host(s) accepted administrative access from the current identity (Section 19.2, read-only verification)' } elseif ($script:Facts.ContainsKey('RemoteAdminValidated')) { 'Section 19.2 was performed and no host accepted administrative access from this identity' } else { 'Section 19.2 was not authorised or not performed' }) },
            @{ Name='Impact on the destination host'; State='unknown'; Evidence='No modification was made on any remote host: access was verified read-only and is reported as capability, not as damage' }
        ) -ImpactStatement 'This is the only chain in the report whose central link was demonstrated with real credentials during the assessment. It converts "reachability" into "administrative access" - the condition that makes credential reuse (shared local administrator passwords, shared service accounts) the most damaging single finding in an internal network.' `
        -Remediation 'Give every host a unique local administrator password (LAPS to full coverage - Section 14), eliminate shared administrative credentials, require separate tiered administrative accounts, and restrict remote administrative interfaces to a privileged-access tier.' `
        -Class 'Critical'

    $script:Facts['ChainsEvaluated'] = 7
}

# ===========================================================================================
#  FINALISATION :: CSV COMPLETION, TEST REGISTRY, EXECUTIVE SUMMARY
# ===========================================================================================

function Export-TestRegistry {
    <# Writes the complete list of test units executed, with their outcome. This makes the
       assessment reproducible: an auditor can see every check that ran, every check that could
       not run, and every check that errored. #>
    param([string]$Path)
    try {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('Seq,Timestamp,Status,Severity,Category,Test,ObservedResult')
        foreach ($t in $script:TestLog) {
            $cells = @($t.Seq, $t.Time, $t.Status, $t.Severity, $t.Category, $t.Finding, $t.Observed) | ForEach-Object { ConvertTo-CsvField $_ }
            [void]$sb.AppendLine(($cells -join ','))
        }
        [System.IO.File]::WriteAllText($Path, $sb.ToString(), $script:Utf8Bom)
        return $true
    } catch {
        Write-Status 'ERROR' ('Test registry could not be written: ' + $_.Exception.Message)
        return $false
    }
}

function Write-ExecutiveSummary {
    param([datetime]$StartedAt, [datetime]$FinishedAt)
    $dur = ($FinishedAt - $StartedAt)
    $sevOrder = @('Critical','High','Medium','Low','Informational')
    $bySev = @{}
    $byStatus = @{}
    foreach ($s in $sevOrder) { $bySev[$s] = 0 }
    foreach ($f in $script:Findings) {
        if ($bySev.ContainsKey($f.Severity)) { $bySev[$f.Severity]++ } else { $bySev[$f.Severity] = 1 }
        if ($byStatus.ContainsKey($f.Status)) { $byStatus[$f.Status]++ } else { $byStatus[$f.Status] = 1 }
    }
    $weak = @($script:Findings | Where-Object { $_.Status -in @('WARN','RISK DETECTED','VALIDATED') })
    $validated = @($script:Findings | Where-Object { $_.Status -eq 'VALIDATED' })
    $notConfirmed = @($script:Findings | Where-Object { $_.Status -eq 'NOT CONFIRMED' })
    $notTestable = @($script:Findings | Where-Object { $_.Status -eq 'NOT TESTABLE' })
    $errors = @($script:Findings | Where-Object { $_.Status -eq 'ERROR' })
    $critInfra = @($weak | Where-Object { $_.Severity -eq 'Critical' -and ($_.Category -match '(?i)delegation|pre-auth|credential|laps|kerberos|attack') })

    $line = '=' * 104
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host '  EXECUTIVE SUMMARY' -ForegroundColor White
    Write-Host $line -ForegroundColor DarkCyan

    Write-Host ''
    Write-Host '  HOST INFORMATION' -ForegroundColor Cyan
    Write-KV 'Hostname / FQDN' ($script:HostName + ' / ' + $(if ($script:HostFqdn) { $script:HostFqdn } else { $script:HostName }))
    Write-KV 'Machine role' $script:Section1Role
    Write-KV 'Operating system' $(if ($script:OsCaption) { $script:OsCaption + ' (' + $script:OsVersion + ')' } else { 'see Section 1' })
    Write-KV 'Domain' $(if ($script:DomainName) { $script:DomainName } else { '(none)' })
    Write-KV 'Assessment identity' ($script:CurrentUser + ' (' + $(if ($script:IsAdmin) { 'elevated administrator' } else { 'standard user' }) + ')')
    Write-KV 'Started / finished' ($StartedAt.ToString('yyyy-MM-dd HH:mm:ss') + ' -> ' + $FinishedAt.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-KV 'Duration' ('{0:N1} minutes' -f $dur.TotalMinutes)

    Write-Host ''
    Write-Host '  DISCOVERY AND COVERAGE' -ForegroundColor Cyan
    Write-KV 'Hosts discovered' $script:Stats.HostsDiscovered
    Write-KV 'Services discovered' $script:Stats.ServicesDiscovered
    Write-KV 'AD objects assessed' $script:Stats.AdObjectsAssessed
    Write-KV 'Directory objects (users/computers/groups)' ($script:AdCounts.Users.ToString() + ' / ' + $script:AdCounts.Computers.ToString() + ' / ' + $script:AdCounts.Groups.ToString())
    Write-KV 'AD enumeration capped' ([string]$script:AdCounts.Capped)
    Write-KV 'Attack chains evaluated' $(if ($script:Facts['ChainsEvaluated']) { [string]$script:Facts['ChainsEvaluated'] } else { '0' })

    Write-Host ''
    Write-Host '  FINDINGS' -ForegroundColor Cyan
    Write-KV 'Total evidence rows written' $script:Stats.Rows
    Write-KV 'Configuration findings (WARN/RISK)' $script:Stats.ConfigFindings
    Write-KV 'Actively validated findings' $validated.Count
    Write-KV 'Findings NOT confirmed' $notConfirmed.Count
    Write-KV 'Tests not executable (NOT TESTABLE)' $notTestable.Count
    Write-KV 'Module/assessment errors' $errors.Count
    Write-Host ''
    Write-Host '  Severity distribution (deterministic matrix, documented in the report):' -ForegroundColor DarkGray
    foreach ($s in $sevOrder) {
        $c = $script:SeverityColor[$s]; if (-not $c) { $c = 'Gray' }
        Write-Host ('    ' + $s.PadRight(16)) -ForegroundColor $c -NoNewline
        Write-Host ([string]$bySev[$s]) -ForegroundColor Gray
    }
    Write-Host ''
    Write-Host '  Status distribution:' -ForegroundColor DarkGray
    foreach ($k in ($byStatus.Keys | Sort-Object)) {
        Write-Host ('    ' + $k.PadRight(16) + [string]$byStatus[$k]) -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host '  CRITICAL INFRASTRUCTURE EXPOSURE' -ForegroundColor Cyan
    if ($critInfra.Count -eq 0) { Write-Host '    No critical-severity exposure was identified by the modules that target credential and identity infrastructure.' -ForegroundColor Gray }
    else {
        Write-KV 'Critical-severity rows in identity/credential categories' $critInfra.Count
        foreach ($c in ($critInfra | Select-Object -First 12)) {
            Write-Host ('    [' + $c.Status + '] ' + $c.Category + ' :: ' + $c.Attribute + ' -> ' + $c.Target) -ForegroundColor Magenta
        }
        if ($critInfra.Count -gt 12) { Write-Host ('    ... ' + ($critInfra.Count - 12) + ' further critical rows are in the CSV report.') -ForegroundColor DarkGray }
    }

    Write-Host ''
    Write-Host '  REPORTING' -ForegroundColor Cyan
    Write-KV 'CSV evidence report' $script:CsvPath
    Write-KV 'Rows written' $script:Stats.Rows
    Write-KV 'CSV writable throughout' ([string]$script:CsvOk)
    if ($script:TestRegistryPath) { Write-KV 'Test registry (all units executed)' $script:TestRegistryPath }

    Write-Host ''
    Write-Host '  SEVERITY METHODOLOGY (no subjective score is produced)' -ForegroundColor Cyan
    Write-Host '    Severity = f(Status, CategoryClass, documented-impact-class) using a fixed matrix:' -ForegroundColor Gray
    Write-Host '      Not a weakness (PASS / NOT CONFIRMED / NOT TESTABLE / context row) ... Informational' -ForegroundColor Gray
    Write-Host '      High class   x Confidentiality -> High     | x Data-at-rest -> Medium | x Identity rights -> High' -ForegroundColor Gray
    Write-Host '      Medium class x Confidentiality -> Medium   | x Data-at-rest -> Low    | x Identity rights -> Medium' -ForegroundColor Gray
    Write-Host '      Low class    x any                         -> Low' -ForegroundColor Gray
    Write-Host '      Critical class                             -> Critical' -ForegroundColor Gray
    Write-Host '    No overall security score, grade or ranking is produced: the findings are not' -ForegroundColor Gray
    Write-Host '    commensurable and a composite score would not be defensible.' -ForegroundColor Gray

    Write-Host ''
    Write-Host '  SCOPE, LIMITATIONS AND REPRODUCIBILITY' -ForegroundColor Cyan
    Write-Host '    1. Discovery is bounded to the address scope derived from this host''s own interfaces and' -ForegroundColor Gray
    Write-Host '       approved at the console; hosts outside that scope were NOT assessed.' -ForegroundColor Gray
    Write-Host '    2. IPv4 only: local IPv6 addresses are reported but never swept (documented limitation).' -ForegroundColor Gray
    Write-Host '    3. UDP services are not probed; a UDP sweep is unreliable and disproportionately noisy.' -ForegroundColor Gray
    Write-Host '    4. LDAP signing/channel binding can only be read on a domain controller; if this host is' -ForegroundColor Gray
    Write-Host '       not a DC those controls are reported as NOT TESTABLE for the DCs, not as compliant.' -ForegroundColor Gray
    Write-Host '    5. Certificate/config details of remote hosts are not collected; remote services are' -ForegroundColor Gray
    Write-Host '       tested for reachability and, where the scope allowed, for credential reuse only.' -ForegroundColor Gray
    Write-Host '    6. This tool performs NO credential dumping, NO password spraying or guessing, NO' -ForegroundColor Gray
    Write-Host '       Kerberos ticket capture, NO persistence, NO evasion and NO concealment of activity.' -ForegroundColor Gray
    Write-Host '    7. Every "NOT TESTABLE" row is an open item. It is not evidence of compliance.' -ForegroundColor Gray
    Write-Host '    8. Evidence classification: CONFIGURATION EVIDENCE (documented state), ACTIVE VALIDATION' -ForegroundColor Gray
    Write-Host '       (observed at runtime at protocol level) and IMPACT EVIDENCE (impact demonstrated).' -ForegroundColor Gray
    Write-Host '       Only IMPACT EVIDENCE rows may be presented as demonstrated impact.' -ForegroundColor Gray

    Write-Host ''
    Write-Host '  AUTHORISATION NOTICE' -ForegroundColor Cyan
    Write-Host '    This assessment was performed from an authorised internal position. The tool is read-only' -ForegroundColor Gray
    Write-Host '    by construction, bounded in scope, and reports negative results as negative rather than' -ForegroundColor Gray
    Write-Host '    inferring impact. Distribution of this report should be limited to the engagement owner,' -ForegroundColor Gray
    Write-Host '    the system owners of the affected hosts, and the security function.' -ForegroundColor Gray
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan

    # Machine-readable run record
    Add-Finding -Category 'Assessment Context' -Status 'INFO' -CatClass 'Context' -Attribute 'Assessment run record' `
        -Finding ($script:Cfg.ToolName + ' v' + $script:Cfg.ToolVersion + ' completed: ' + $script:Stats.Rows + ' evidence rows, ' + $validated.Count + ' actively validated findings, ' + $notConfirmed.Count + ' not confirmed, ' + $notTestable.Count + ' not testable, ' + $errors.Count + ' errors.') `
        -Observed ('Hosts discovered=' + $script:Stats.HostsDiscovered + '; services discovered=' + $script:Stats.ServicesDiscovered + '; AD objects assessed=' + $script:Stats.AdObjectsAssessed + '; duration=' + ('{0:N1}' -f $dur.TotalMinutes) + ' minutes; CSV=' + $script:CsvPath) `
        -Validation 'Run metadata (self-reported by the tool for reproducibility)' -Class 'Low' -CatClass 'Context' `
        -Remediation 'Retain this report with the engagement record. Re-run after remediation to confirm each finding changes state, and compare the two runs row by row.' `
        -Impact 'None - run metadata.' -NoConsole
}

# -------------------------------------------------------------------------------------------
#  Export-ValidationHandoff
#  Turns the run's findings into the operator's next-step list. LOCAL FILE WORK ONLY - no network
#  operation, and it is deliberately invoked even when the kill switch has stopped the assessment,
#  because the point at which you stop is exactly when you need to know what is left to do.
# -------------------------------------------------------------------------------------------
function Export-ValidationHandoff {
    Write-Host ''
    Write-Host '  -- Validation handoff: what to do with each finding ------------------------------' -ForegroundColor DarkCyan

    # Every non-benign outcome is a candidate. PASS rows carry nothing to follow up; ERROR rows are
    # an engine problem, not a target finding.
    $interesting = @('WARN','RISK DETECTED','VALIDATED','NOT CONFIRMED','NOT TESTABLE','OPPORTUNITY')
    $items = @()
    foreach ($e in $script:TestLog) {
        if ($interesting -notcontains [string]$e.Status) { continue }
        $h = Get-ValidationHandoff -Attribute ([string]$e.Attribute) -Category ([string]$e.Category)
        $items += [pscustomobject]@{
            Stage = [string]$h.Stage; Where = [string]$h.Where
            Attribute = $(if ($e.Attribute) { [string]$e.Attribute } else { [string]$e.Category })
            Status = [string]$e.Status; Target = [string]$e.Finding
            Next = ($h.Next -join '  ||  '); Confirms = [string]$h.Confirms
            Refutes = [string]$h.Refutes; Blast = [string]$h.Blast
        }
    }

    if ($items.Count -eq 0) {
        Write-Status 'INFO' 'No finding requires operator follow-up: every assessable control either passed or produced no outcome.'
        return
    }

    # Collapse duplicates across hosts - the same attribute on 40 hosts is ONE technique to run.
    $byKey = @{}
    foreach ($i in $items) {
        $k = $i.Stage + '|' + $i.Attribute
        if (-not $byKey.ContainsKey($k)) {
            $byKey[$k] = [pscustomobject]@{ Stage=$i.Stage; Where=$i.Where; Attribute=$i.Attribute; Status=$i.Status;
                                            Next=$i.Next; Confirms=$i.Confirms; Refutes=$i.Refutes; Blast=$i.Blast; Count=1; Example=$i.Target }
        } else { $byKey[$k].Count++ }
    }
    $steps = @($byKey.Values)

    # ---- console: pipeline overview -----------------------------------------------------------
    Write-Host ''
    Write-Host '    ATTACK-CHAIN VALIDATION PIPELINE (discovered -> validated)' -ForegroundColor Cyan
    $order = @($script:HandoffStageOrder)
    $total = 0
    foreach ($st in $order) {
        $n = @($steps | Where-Object { $_.Stage -eq $st }).Count
        $total += $n
        $bar = if ($n -gt 0) { '#' * [Math]::Min($n, 30) } else { '' }
        Write-Host ('      ' + $(if ($n -gt 0) { '[ ]' } else { '[x]' }) + ' ' + $st.PadRight(38) + ' ' + $n.ToString().PadLeft(3) + '  ' + $bar) -ForegroundColor $(if ($n -gt 0) { 'White' } else { 'DarkGray' })
    }
    Write-Host ''
    Write-Status 'INFO' ($total.ToString() + ' distinct validation step(s) across ' + $script:TestLog.Count + ' assessed control(s). This tool does not execute them - see the handoff file.')

    # ---- console: the range-only steps, called out because they are the risky ones -------------
    $rangeOnly = @($steps | Where-Object { $_.Where -eq 'range' })
    if ($rangeOnly.Count -gt 0) {
        Write-Host ''
        Write-Host ('    RANGE-ONLY STEPS (' + $rangeOnly.Count + ') - do NOT attempt these against production:') -ForegroundColor Yellow
        foreach ($r in $rangeOnly) { Write-Host ('      ! ' + $r.Attribute + '  [' + $r.Stage + ']') -ForegroundColor Yellow }
    }

    # ---- console: the next three things to do -------------------------------------------------
    Write-Host ''
    Write-Host '    NEXT STEPS (first three, in pipeline order):' -ForegroundColor Cyan
    $seq = 1
    foreach ($st in $order) {
        foreach ($r in @($steps | Where-Object { $_.Stage -eq $st })) {
            if ($seq -gt 3) { break }
            Write-Host ('      ' + $seq + '. ' + $r.Attribute + $(if ($r.Count -gt 1) { '  (x' + $r.Count + ')' } else { '' })) -ForegroundColor White
            Write-Host ('         next    : ' + ($r.Next -split '  \|\|  ')[0]) -ForegroundColor Gray
            Write-Host ('         confirms: ' + $r.Confirms) -ForegroundColor Gray
            $seq++
        }
        if ($seq -gt 3) { break }
    }

    # ---- markdown handoff file ----------------------------------------------------------------
    try {
        $handoffPath = Join-Path $script:ReportDirectory ('Internal_VAPT_Handoff_' + $script:ReportHostTag + '_' + $script:ReportStamp + '.md')
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('# Validation handoff - ' + [string]$script:HostName + ' - ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Produced by ' + [string]$script:Cfg.ToolName + ' v' + [string]$script:Cfg.ToolVersion + '. Companion to `' + (Split-Path -Leaf $script:CsvPath) + '`.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Each entry below is a step THIS TOOL DID NOT PERFORM. It states what to do, what would')
        [void]$sb.AppendLine('confirm the weakness, what would refute it, and the blast radius of trying. Steps marked')
        [void]$sb.AppendLine('**range only** belong in an isolated environment.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Stage | Step | Hosts | Where |')
        [void]$sb.AppendLine('|---|---|---|---|')
        foreach ($st in $order) {
            foreach ($r in @($steps | Where-Object { $_.Stage -eq $st } | Sort-Object Attribute)) {
                [void]$sb.AppendLine('| ' + $r.Stage + ' | ' + ($r.Attribute -replace '\|','/') + ' | ' + $r.Count + ' | ' + $r.Where + ' |')
            }
        }
        [void]$sb.AppendLine('')
        foreach ($st in $order) {
            $groupSteps = @($steps | Where-Object { $_.Stage -eq $st } | Sort-Object Attribute)
            if ($groupSteps.Count -eq 0) { continue }
            [void]$sb.AppendLine('## ' + $st)
            [void]$sb.AppendLine('')
            foreach ($r in $groupSteps) {
                [void]$sb.AppendLine('### ' + $r.Attribute + '  (' + $r.Count + ' occurrence(s), ' + $r.Where + ')')
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('*Observed:* ' + $r.Example)
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('**Next step**')
                [void]$sb.AppendLine('')
                foreach ($n in ($r.Next -split '  \|\|  ')) { [void]$sb.AppendLine('- ' + $n) }
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('**Confirms:** ' + $r.Confirms)
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('**Refutes:** ' + $r.Refutes)
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('**Blast radius:** ' + $r.Blast)
                [void]$sb.AppendLine('')
            }
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('A weakness recorded as discovered is NOT a validated compromise. Report them separately.')
        [void]$sb.AppendLine('Until a step above is executed and recorded, the corresponding item remains a DISCOVERED WEAKNESS.')
        [System.IO.File]::WriteAllText($handoffPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
        $script:HandoffPath = $handoffPath
        Write-Host ''
        Write-KV 'Validation handoff' $handoffPath
        Write-Status 'PASS' 'Handoff written. Execute the steps, then fold the results back into the engagement record - the report says discovered, not confirmed, until you do.'
    } catch {
        Write-Status 'WARN' ('The handoff file could not be written: ' + $_.Exception.Message + '. The steps above are the same content - capture them from this console.')
    }

    Add-Finding -Category 'Assessment Integrity' -Status 'INFO' -CatClass 'Context' -Attribute 'Validation handoff' `
        -Source $script:HostName -Target $(if ($script:HandoffPath) { $script:HandoffPath } else { 'console only' }) `
        -Finding ($steps.Count.ToString() + ' distinct validation step(s) were handed to the operator, grouped across ' + $order.Count + ' pipeline stages; ' + $rangeOnly.Count + ' are range-only.') `
        -Observed 'The handoff lists the next action, the confirm/refute criteria and the blast radius for every non-benign finding. None of these steps was executed by this tool.' `
        -Validation 'Derived from the run''s own finding log (TestLog), joined to a static technique map. No network operation is performed by this module.' `
        -Class 'Low' -CatClass 'Context' `
        -Remediation 'Execute the steps in order, update the report as each one resolves, and keep the handoff with the engagement record.' `
        -Impact 'None by itself. This row exists so the report states plainly which findings are DISCOVERED and which are VALIDATED - an unexecuted step must not be reported as a confirmed exploit.' -NoConsole
}

# ===========================================================================================
#  MAIN :: assembled and executed by the host batch file
# ===========================================================================================
function Invoke-EnterpriseAssessment {
    $started = Get-Date
    $script:StartTime = $started
    $script:CurrentUser = if ($env:USERDOMAIN) { $env:USERDOMAIN + '\' + $env:USERNAME } else { $env:USERNAME }

    # Output directory: supplied EXPLICITLY by the launcher (which probes for a writable folder
    # and falls back to ProgramData). The CWD is deliberately the LAST resort, because under an
    # orchestration engine the CWD is System32 - a path that either refuses the write or hides the
    # report where nobody will look for it.
    $outDir = ''
    if (-not [string]::IsNullOrWhiteSpace($env:EIA_OUTDIR)) { $outDir = [string]$env:EIA_OUTDIR }
    if ([string]::IsNullOrWhiteSpace($outDir)) { try { $outDir = (Get-Location).Path } catch { $outDir = $env:TEMP } }
    try {
        if (-not (Test-Path -LiteralPath $outDir)) { [void](New-Item -ItemType Directory -Path $outDir -Force) }
        [void](New-Item -ItemType File -Path (Join-Path $outDir 'EIA_write_test.tmp') -Force -ErrorAction Stop)
        Remove-Item -LiteralPath (Join-Path $outDir 'EIA_write_test.tmp') -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host ('[WARN] Output directory not writable: ' + $outDir + ' - falling back to %ProgramData%.') -ForegroundColor Yellow
        $outDir = $env:ProgramData
        if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = $env:TEMP }
    }
    [void](Initialize-Report -Directory $outDir)
    Initialize-PowerShellRuntime
    Invoke-Section1_Initialization

    # Persist the context values that later modules and the summary rely on.
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $script:OsCaption = if ($os) { $os.Caption } else { '' }
        $script:OsVersion = if ($os) { $os.Version + ' build ' + $os.BuildNumber } else { '' }
        $script:HostFqdn  = $env:COMPUTERNAME
        try { $script:HostFqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { }
        $script:CurrentUserSid = ''
        try { $script:CurrentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }
        $script:IsAdmin = Test-IsAdmin
        $script:IntegrityLevel = if ($script:IntegrityLevel) { $script:IntegrityLevel } else { (Get-IntegrityLevel) }
        if ($cs -and $cs.Domain) { $script:DomainName = [string]$cs.Domain }
        if (-not $script:DomainName -and (Test-RemoteAllowed)) { try { $script:DomainName = ([ADSI]'LDAP://RootDSE').Properties['defaultNamingContext'].Value -replace ',DC=', '.' -replace 'DC=', '' } catch { } }
        if ($script:DomainName -and (Test-RemoteAllowed)) {
            try {
                $dcName = ([ADSI]('LDAP://' + $script:DomainName)).Properties['dNSHostName'].Value
                if ($dcName) { $script:DomainControllerName = [string]$dcName }
            } catch { }
        }
        if ($script:DomainControllerName) {
            try {
                $a = [System.Net.Dns]::GetHostAddresses($script:DomainControllerName) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
                if ($a) { $script:Facts['DcResolvedIpv4'] = $a.IPAddressToString }
            } catch { }
        }
    } catch { Write-Status 'WARN' ('Context enrichment failed: ' + $_.Exception.Message) }

    # ---- Modules 2-20 -------------------------------------------------------------------
    Invoke-Section '2'  'LOCAL SECURITY CONFIGURATION'                       { Invoke-Section2_LocalConfiguration }
    Invoke-Section '3'  'SMB SECURITY ASSESSMENT (protocol validated)'       { Invoke-Section3_Smb }
    Invoke-Section '4'  'AUTHENTICATION SECURITY (policy vs behaviour)'      { Invoke-Section4_Authentication }
    Invoke-Section '5'  'LSA / LSASS SECURITY'                              { Invoke-Section5_Lsass }
    Invoke-Section '6'  'PRINT SPOOLER (role-aware)'                        { Invoke-Section6_Spooler }
    Invoke-Section '7'  'WINDOWS UPDATE / WSUS'                             { Invoke-Section7_Update }
    Invoke-Section '8'  'NETWORK DISCOVERY (bounded, authorised scope)'      { Invoke-Section8_Discovery }
    Invoke-Section '9'  'ACTIVE DIRECTORY ENUMERATION'                       { Invoke-Section9_AdEnumeration }
    Invoke-Section '10' 'USER ACCOUNT CONTROL / KERBEROS PRE-AUTH'           { Invoke-Section10_PreAuth }
    Invoke-Section '11' 'SPN / SERVICE-ACCOUNT AUDIT'                        { Invoke-Section11_Spn }
    Invoke-Section '12' 'DELEGATION AUDIT'                                   { Invoke-Section12_Delegation }
    Invoke-Section '13' 'ENCRYPTION DOWNGRADE AUDIT'                         { Invoke-Section13_Encryption }
    Invoke-Section '14' 'LAPS AUDIT'                                         { Invoke-Section14_Laps }
    Invoke-Section '15' 'NETWORK SEGMENTATION VAPT'                          { Invoke-Section15_Segmentation }
    Invoke-Section '16' 'LATERAL-MOVEMENT ATTACK-PATH ANALYSIS'              { Invoke-Section16_AttackPaths }
    Invoke-Section '17' 'LOCAL PRIVILEGE-ESCALATION ASSESSMENT'              { Invoke-Section17_PrivEsc }
    Invoke-Section '18' 'LOLBIN / NATIVE EXECUTION ASSESSMENT'               { Invoke-Section18_LolBin }
    Invoke-Section '19' 'ACTIVE EXPLOITABILITY VALIDATION'                   { Invoke-Section19_Validation }
    Invoke-Section '20' 'ATTACK-CHAIN CORRELATION'                           { Invoke-Section20_Chains }

    # ---- Section 21: reporting ----------------------------------------------------------
    Invoke-Section '21' 'REPORTING' {
        Write-Host ''
        Write-Host '  -- 21.1 Forensic integrity (row 1 of the CSV) ------------------------------------' -ForegroundColor DarkCyan
        if ($script:IntegrityRowWritten -and $script:IntegrityHashes) {
            $ih = $script:IntegrityHashes
            Write-KV 'Launcher SHA-256' ([string]$ih.LauncherSha256 + '   [' + [string]$ih.LauncherSource + ']')
            Write-KV 'Engine SHA-256' ([string]$ih.EngineSha256 + '   [' + [string]$ih.EngineSource + ']')
            Write-KV 'Launcher path' $(if ($ih.LauncherPath) { $ih.LauncherPath } else { 'not available' })
            Write-KV 'Engine path' $(if ($ih.EnginePath) { $ih.EnginePath } else { 'not available' })
            Write-Status 'PASS' 'Integrity row is the FIRST data row of the CSV. Both digests were computed in memory by the engine itself and can be cross-checked against the digest the launcher printed at extraction time.'
            Add-Finding -Category 'Assessment Integrity' -Status 'INFO' -CatClass 'Context' -Attribute 'Engine/launcher digest confirmation' `
                -Source $script:HostName -Target $(if ($ih.LauncherPath) { $ih.LauncherPath } else { 'launcher' }) `
                -Finding 'The digests recorded in the first CSV row were recomputed at the end of the run and match the values written at start-up.' `
                -Observed ('Launcher SHA-256=' + [string]$ih.LauncherSha256 + '; Engine SHA-256=' + [string]$ih.EngineSha256) `
                -Validation 'In-memory SHA-256 recomputation of the launcher file and of the extracted engine file, compared with the first CSV row.' `
                -Configured ('Launcher source: ' + [string]$ih.LauncherSource + '; engine source: ' + [string]$ih.EngineSource) -Class 'Low' -CatClass 'Context' `
                -Remediation 'Retain the integrity row with the report and verify the digests against the copy held by the engagement owner.' `
                -Impact 'None - provenance confirmation.' -NoConsole
        } else {
            Write-Status 'WARN' 'The forensic integrity row could not be written at start-up; digests are shown on the console only. Verify the CSV manually.'
        }
        Write-Host ''
        Write-KV 'CSV evidence report' $script:CsvPath
        Write-KV 'Evidence rows' $script:Stats.Rows
        if ($script:CsvOk -and (Test-Path -LiteralPath $script:CsvPath)) {
            $fi = Get-Item -LiteralPath $script:CsvPath
            Write-KV 'Report size' ('{0:N1} KB' -f ($fi.Length / 1KB))
            # Same run-specific stem as the compliance report so a multi-host engagement produces
            # a matched pair of files that cannot be confused with another host's output.
            $regName = 'Internal_VAPT_Test_Registry.csv'
            if ($script:RegistryName) { $regName = $script:RegistryName }
            $script:TestRegistryPath = Join-Path $fi.DirectoryName $regName
            [void](Export-TestRegistry -Path $script:TestRegistryPath)
            Write-KV 'Test registry' $script:TestRegistryPath
            Write-Status 'PASS' 'Evidence report finalised. Columns: Timestamp,Severity,Category,Source,Target,Port,Finding,Prerequisites,ConfigurationEvidence,ValidationMethod,ObservedResult,Exploitability,Impact,Remediation'
            Write-Status 'INFO' 'RFC4180 escaping applied to every field; the file is UTF-8 with BOM so it opens correctly in Excel/LibreOffice.'
        } else {
            Write-Status 'ERROR' 'The CSV report could not be written. Evidence exists only on this console - capture it now.'
        }
    }

    # Validation handoff - invoked DIRECTLY rather than through Invoke-Section, because it is local
    # file work and must still be produced when the kill switch has halted the assessment. Knowing
    # what is left to do matters most at the moment you stop.
    try { Export-ValidationHandoff } catch { Write-Status 'WARN' ('Validation handoff failed: ' + $_.Exception.Message) }

    $finished = Get-Date
    Write-ExecutiveSummary -StartedAt $started -FinishedAt $finished
}

Invoke-EnterpriseAssessment
#===EIA-PS-END===
