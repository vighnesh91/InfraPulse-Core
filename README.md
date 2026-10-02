# InfraPulse-Core

InfraPulse-Core is a unified, dual-platform security auditing architecture implementing single-file, zero-dependency engines for Linux (`POSIX`) and Windows (`Win32`). 

Unlike traditional vulnerability scanners that rely on subjective risk metrics, InfraPulse-Core enforces an unyielding **Evidence-Tuple Model**, programmatically segregating static **Configuration Evidence** from **Active Protocol Validation** and **Demonstrated Impact**.

## 🛡️ Core Guarantees & Architectural Safeties

1. **The Single Socket Choke Point**: Network egress is programmatically impossible without passing a single validation gate (`socket_gate` / `Test-TargetAllowed`). This gate evaluates the operator-supplied scope against a default-deny policy before a socket is instantiated.
2. **Zero-Mutation Footprint**: The engines are strictly read-only. They do not inject processes, modify system registries, write to system binaries, harvest cleartext credentials, or execute disruptive exploits.
3. **Forensic Integrity Tracing**: The very first data row of the generated CSV report computes an in-memory SHA-256 hash of the executing engine. This ties the resulting dataset explicitly to an audited codebase block.
4. **Deterministic Severity Mapping**: Eliminates subjective scoring. Vulnerabilities are automatically rated based on a combination of their category class, verified runtime state, and exposure preconditions.

## 📁 Repository Layout

```text
InfraPulse-Core/
├── src/
│   ├── posix/
│   │   └── InfraPulse-LX.sh      # Linux Native Bash Engine
│   └── win32/
│       └── InfraPulse-Win.bat    # Windows Native Extraction/PowerShell Engine
├── LICENSE                       # MIT License terms
└── README.md                     # Main deployment guide
```

## 💻 Operational Execution Modes

### 🟢 POSIX Audit (`src/posix/InfraPulse-LX.sh`)
Ensure execution permissions are granted before deployment:
```bash
chmod +x InfraPulse-LX.sh
```
```bash
# Execute local hardening profile with absolute network containment
./InfraPulse-LX.sh --local-only

# Execute network discovery over tightly bounded, authorised CIDR limits
./InfraPulse-LX.sh --scope 10.10.20.0/24,!10.10.20.254
```

### 🔵 WinRM & Active Directory Audit (`src/win32/InfraPulse-Win.bat`)
*Run from an Elevated Command Prompt for maximum filesystem/LSA tracking accuracy.*
```cmd
:: Suppress outbound queries; audit loopback and local OS protections only
InfraPulse-Win.bat /localonly

:: Target a specific segment with an automated default-deny network stance
InfraPulse-Win.bat /scope:172.16.4.0/24,!172.16.4.10
```

## 📊 Output Artifacts

The engine splits verification tasks across two discrete files dynamically dropped into the output directory:
* **The Compliance Report (`*.csv`)**: Formatted precisely to RFC4180 rules. Tracks entries using a 14-column layout mapping: `Timestamp`, `Severity`, `Category`, `Source`, `Target`, `Port`, `Finding`, `Prerequisites`, `ConfigurationEvidence`, `ValidationMethod`, `ObservedResult`, `Exploitability`, `Impact`, and `Remediation`.
* **The Actionable Handoff (`*.md`)**: Generates an ordered, pipeline-style manual playbook. It provides the exact steps a human operator must perform to confirm or refute a vulnerability, along with a pre-calculated engineering blast radius for each check.
