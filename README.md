<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Server%202016+-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Language-C-A8B9CC?style=for-the-badge&logo=c&logoColor=white" alt="Language">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Edition-Community-blue?style=for-the-badge" alt="Edition">
</p>

# EdrShield

**Prevent attackers from silencing your EDR.**

EdrShield is a lightweight Windows service that defends Endpoint Detection and Response agents against WFP (Windows Filtering Platform) and QoS (Quality of Service) tampering attacks. When an attacker with admin access installs hostile network filters to cut off your EDR's cloud communication, EdrShield detects and removes them within seconds -- keeping your telemetry pipeline alive.

---

## The Problem

A growing class of attack tools -- **EDR Silencers** and **EDR Killers** -- exploit a fundamental gap in endpoint security. Instead of disabling the EDR process (which triggers alerts), they **block its network communication**:

```
Attacker gains admin access
        |
        v
Installs WFP BLOCK filters targeting EDR processes
   -- or --
Creates QoS policies throttling EDR bandwidth to 1 bit/sec
        |
        v
EDR agent keeps running (no crash, no alert)
but CANNOT reach its cloud backend
        |
        v
No telemetry sent. No commands received.
The EDR is blind. The attacker operates freely.
```

This technique is actively used in ransomware operations. The EDR appears healthy in every local check -- its processes are running, its services are started -- but it is effectively dead. Security teams have no visibility into what is happening on the compromised host.

**EdrShield closes this gap.**

---

## How It Works

```
                    EdrShield Service
                          |
            +-------------+-------------+
            |                           |
     WFP Monitor (1s)           QoS Monitor (5s)
            |                           |
   Enumerate all WFP           Query all QoS policies
   BLOCK filters                        |
            |                  Detect policies targeting
   Check each filter:          EDR process bandwidth
   - Targets EDR process?              |
   - From trusted provider?    Remove hostile policies
   - Legitimate containment?           |
            |                  Log to Event Log
   Trusted? SKIP.                      
   Hostile? REMOVE.                    
            |                          
   Place PERMIT filters                
   in EdrShield sublayer               
            |                          
   Log to Event Log                    
```

EdrShield runs two continuous monitoring loops:

| Monitor | Interval | What It Does |
|---------|----------|--------------|
| **WFP Scanner** | Every 1 second | Enumerates all WFP BLOCK/DROP filters. For each filter targeting a known EDR process, verifies whether it belongs to a trusted provider. Removes only hostile filters. Places protective PERMIT filters. |
| **QoS Scanner** | Every 5 seconds | Queries Windows QoS policies. Detects policies that throttle EDR process bandwidth. Removes hostile throttling policies. |

### Trusted Provider Verification

EdrShield never removes a legitimate filter. Before acting on any WFP filter, it checks four dimensions:

| Check | Purpose |
|-------|---------|
| **Filter name** | Matches against known EDR filter name patterns (e.g., "Microsoft Defender", "MpFilter") |
| **Provider name** | Matches against known vendor strings (e.g., "Microsoft Corporation") |
| **Provider GUID** | Validates against dynamically discovered trusted provider GUIDs |
| **Service path** | Checks the provider's service registry path for known EDR install directories |

If any check matches a trusted source, the filter is left untouched -- even if it blocks an EDR process. This preserves legitimate EDR containment functionality.

---

## Quick Start

### 1. Build

Requires [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) (MSVC).

```batch
build.bat
```

Output: `build\edrshield.exe`

### 2. Install

Run from an elevated (Administrator) command prompt:

```batch
edrshield.exe install
```

### 3. Start

```batch
sc start EdrShieldSvc
```

EdrShield is now monitoring. Any hostile WFP filters or QoS throttling policies will be detected and removed automatically.

---

## Usage

| Command | Description |
|---------|-------------|
| `edrshield.exe install` | Install as a Windows service (`EdrShieldSvc`) |
| `edrshield.exe uninstall` | Remove the service |
| `edrshield.exe monitor` | Run in foreground console mode (for testing/debugging) |
| `edrshield.exe version` | Display version information |

### Logging

EdrShield writes to two destinations:

- **Windows Event Log** -- Source: `EdrShieldSvc`. All detections and remediations are logged with structured event IDs for SIEM integration.
- **File log** -- `C:\ProgramData\EdrShield\edrshield.log`. Detailed operational log with timestamps.

### Event IDs

| Event ID | Meaning |
|----------|---------|
| 2001 | Monitor started |
| 2002 | Hostile WFP filter detected |
| 2003 | Hostile WFP filter removed |
| 2004 | Hostile QoS policy detected |
| 2005 | Hostile QoS policy removed |
| 2006 | Protective PERMIT filter added |
| 2011 | EDR containment filter detected (trusted, not removed) |
| 2012 | Trusted provider discovered |

---

## Protected EDR Processes

The community edition monitors and protects the following Microsoft Defender / MDE processes:

| Process | Role |
|---------|------|
| `MsSense.exe` | Defender for Endpoint sensor |
| `MsMpEng.exe` | Antimalware Service Executable |
| `SenseIR.exe` | Incident Response module |
| `SenseCncProxy.exe` | Command and Control proxy |
| `SenseNdr.exe` | Network Detection and Response |

---

## Project Structure

```
src/
  edrshield.h      Central header, configuration, trusted provider lists
  main.c           Entry point, console and service mode dispatch
  service.c        Windows service lifecycle management
  wfp.c            WFP engine: scan, detect, remediate hostile filters
  qos.c            QoS defense: detect and remove throttling policies
  discovery.c      EDR process discovery and protection
  log.c            Logging (file, console, Windows Event Log)
  wfp_compat.h     MinGW compatibility definitions
build.bat          Build script (MSVC)
LICENSE            MIT License
```

---

## Community Edition vs. Commercial

| Capability | Community | Commercial |
|------------|:---------:|:----------:|
| WFP tamper detection and remediation | Yes | Yes |
| QoS throttling detection and remediation | Yes | Yes |
| Microsoft Defender / MDE protection | Yes | Yes |
| Windows Event Log integration | Yes | Yes |
| Third-party EDR support (15+ vendors) | -- | Yes |
| Anti-tampering self-defense | -- | Yes |
| Protected uninstall | -- | Yes |
| MSI installer with enterprise deployment | -- | Yes |
| Priority support | -- | Yes |

For the commercial edition, contact **alvaro.fraguas@gmail.com**.

---

## Build Requirements

- **OS**: Windows 10/11 or Windows Server 2016+
- **Compiler**: Visual Studio Build Tools 2022 (MSVC, `cl.exe`)
- **Architecture**: x64
- **SDK**: Windows SDK (included with Build Tools)

The build script auto-detects Enterprise, Community, and BuildTools installations of Visual Studio 2022.

---

## References

- [EDR Silencer](https://www.trendmicro.com/en_us/research/24/i/edr-silencer-disrupting-endpoint-security-solutions.html) -- Trend Micro research on WFP-based EDR silencing
- [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) -- Microsoft WFP documentation
- [MITRE ATT&CK: Impair Defenses](https://attack.mitre.org/techniques/T1562/) -- T1562, Defense Evasion

---

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please ensure your code compiles cleanly with `/W4` warning level and follows the existing code style.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Alvaro Fraguas
