# WriteProcess Dumper

A Windows research tool that hooks `WriteProcessMemory` and `VirtualAllocEx` in a target process via DLL injection, logging and dumping every write to disk. Useful for unpacking, shellcode extraction, and studying injection behavior.

---

## How it works

`injector.exe` launches the target executable suspended, injects `dllmain.dll` via `LoadLibraryA` remote thread, then resumes the process. Once loaded, the DLL installs inline JMP hooks on `WriteProcessMemory` and `VirtualAllocEx` inside the target. Every call is intercepted, logged, and the written buffer is saved to a `.bin` file. Writes targeting executable memory regions are tagged `-EXEC` in the filename.

```
Target process
 └─ WriteProcessMemory() ──► Hooked_WriteProcessMemory()
                                 ├─ VirtualQueryEx()       (classify region)
                                 ├─ IsTrackedExecRegion()  (check VAE table)
                                 ├─ IsMZHeader()           (detect PE image)
                                 ├─ Log to .txt
                                 ├─ Dump buffer to .bin
                                 └─ Call original WPM
```

---

## Output files

All files are written next to `dllmain.dll`.

| File | Contents |
|------|----------|
| `WPMDump-<timestamp>.txt` | Full call log with addresses, region info, and MZ warnings |
| `WPMDump-<timestamp>-<N>.bin` | Raw buffer from the Nth `WriteProcessMemory` call |
| `WPMDump-<timestamp>-<N>-EXEC.bin` | Same, but the target region was executable or the buffer was a PE image |

---

## Building

Requires Visual Studio (MSVC) on Windows. Run the provided build script:

```bat
compile.bat   # produces injector.exe (x64) + dllmain.dll (x64)
compile_X86.bat   # produces injector.exe (x86) + dllmain.dll (x86)
```

Manual MSVC build:

```bat
cl.exe /O2 /W4 /EHsc /Fe:injector.exe injector.cxx
cl.exe /O2 /W4 /EHsc /LD /Fe:dllmain.dll dllmain.cxx
```

> **Architecture must match.** Use the x64 build for 64-bit targets and the x86 build for 32-bit targets. The injector will warn and exit if there is a mismatch.

---

## Usage

```
injector.exe
  [?] Path to target .exe : C:\path\to\target.exe
  [?] Path to dumper .dll : C:\path\to\dllmain.dll
```

After confirming with Enter, the injector launches the target suspended, injects the DLL, and resumes. Dump files accumulate in real time next to the DLL. Press `Ctrl+C` to force-terminate early.

---

## Hook details

| API | Patch (x86) | Patch (x64) |
|-----|-------------|-------------|
| `WriteProcessMemory` | `E9 rel32` (5 bytes) | `FF 25 00000000 + abs64` (14 bytes) |
| `VirtualAllocEx` | `E9 rel32` (5 bytes) | `FF 25 00000000 + abs64` (14 bytes) |

Each hook uses a per-hook `CRITICAL_SECTION` to serialise pause/unpause. The original bytes are restored only for the duration of the real call, then the patch is immediately re-applied.

---

## EXEC detection

A write is classified as `-EXEC` if any of the following are true:

- The buffer starts with `MZ` (PE image header)
- The destination address falls within a region previously allocated by `VirtualAllocEx` with an executable protection flag
- `VirtualQueryEx` reports the destination region currently has an executable protection flag

---

## Requirements

- Windows 7 or later
- MSVC (Visual Studio 2019+)
- Administrator privileges may be required depending on the target

---

## Disclaimer

This tool is intended for malware analysis, reverse engineering research, and educational use in controlled environments. Do not use against processes you do not own or have explicit permission to inspect.
