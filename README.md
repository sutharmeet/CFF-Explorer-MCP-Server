# CFF Explorer MCP Server

> **Talk to your PE files.** A Model Context Protocol (MCP) server that bridges [CFF Explorer](https://ntcore.com/?page_id=388)'s powerful Lua scripting engine with Claude AI — enabling natural language PE analysis, import/export inspection, and binary patching.

---

## What Is This?

This project turns **CFF Explorer** — a professional-grade PE file analysis tool — into an AI-accessible tool via the Model Context Protocol. Once set up, you can ask Claude things like:

- *"Analyse the PE headers of `malware.exe` and flag anything suspicious"*
- *"List all imports of `suspicious.dll` and highlight dangerous API calls"*
- *"Extract the manifest resource from `setup.exe`"*
- *"NOP out 5 bytes at offset 0x1A3C in `target.exe`"*
- *"Invert the jump at offset 0x2B10 so the license check always passes"*

...and Claude will use CFF Explorer in headerless under the hood to answer you with structured, interpreted results.

---

## How It Works

```
You (natural language)
        │
        ▼
  Claude Desktop
        │  MCP protocol (stdio)
        ▼
  server.py  ◄─── This project
        │
        │  1. Generates a temporary .cff Lua script
        │  2. Launches CFF Explorer.exe as a subprocess (headless, no GUI)
        │  3. CFF Explorer runs the script, prints results to stdout, exits
        │  4. server.py parses the output into structured JSON
        │
        ▼
  CFF Explorer.exe
  (running invisibly in background for ~1 second)
```

**Key insight:** CFF Explorer has a built-in [Lua scripting engine (v2)](https://ntcore.com/files/cffscriptv2.htm). When you pass a `.cff` script file as a command-line argument, it runs headlessly — no window, no GUI, just script execution and stdout output. This project exploits that to give AI models programmatic access to CFF Explorer's full PE analysis API.

---

## Features

| Tool | Description |
|------|-------------|
| `analyze_pe_headers` | Full PE header dump — DOS, COFF File Header, Optional Header, all sections |
| `list_imports` | All imported DLLs and functions with ordinals |
| `list_exports` | All exported symbols from a DLL |
| `nop_bytes` | Patch: NOP out N bytes at a given file offset |
| `invert_jump` | Patch: Flip a conditional jump (JZ↔JNZ, JE↔JNE, etc.) |
| `extract_resource` | Save a PE resource (icon, manifest, bitmap, etc.) to disk |

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows only (CFF Explorer is Windows-exclusive) |
| **Python** | 3.10 or higher |
| **CFF Explorer** | [Explorer Suite](https://ntcore.com/?page_id=388) — free download |
| **Claude Desktop** | [claude.ai/download](https://claude.ai/download) |

---

## Installation

### Step 1 — Download CFF Explorer

1. Go to [https://ntcore.com/?page_id=388](https://ntcore.com/?page_id=388)
2. Download **Explorer Suite**
3. Install it (default path: `C:\Program Files\Explorer Suite\`)
4. **Important:** Open CFF Explorer GUI → go to **Edit → Preferences** → uncheck **Scripting Privilege Protection (SPP)**

   > SPP shows a GUI consent dialog before certain script operations. In headless mode this dialog blocks forever, causing timeouts. Disable it for the MCP server to work correctly.

### Step 2 — Clone This Repo

```bash
git clone https://github.com/YOUR_USERNAME/cff-explorer-mcp.git
cd cff-explorer-mcp
```

### Step 3 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs only one package: the `mcp` SDK.

### Step 4 — Configure Claude Desktop

Open your Claude Desktop config file:

```
%APPDATA%\Claude\claude_desktop_config.json
```

Add the `cff-explorer` entry under `mcpServers`. See [`claude_desktop_config_example.json`](claude_desktop_config_example.json) for a template:

```json
{
  "mcpServers": {
    "cff-explorer": {
      "command": "python",
      "args": [
        "C:/path/to/cff-explorer-mcp/server.py"
      ],
      "env": {
        "CFF_EXPLORER_PATH": "C:\\Program Files\\Explorer Suite\\CFF Explorer.exe"
      }
    }
  }
}
```

> **Note:** Use your actual Python path. Find it by running `where python` in PowerShell.

### Step 5 — Restart Claude Desktop

Close and reopen Claude Desktop. You should see the CFF Explorer tools available in the tools panel.

---

## Usage Examples

### PE Header Analysis

> *"Analyse the PE headers of C:\samples\suspicious.exe"*

Claude will return:
- Architecture (x86/x64/ARM64)
- Entry point, image base, size
- All sections with virtual/raw sizes, RVAs, and characteristics flags
- Subsystem type (GUI, CUI, Native, etc.)
- Whether it's a .NET assembly
- Suspicious flags (forged timestamp, non-standard image base, section anomalies)

### Import Analysis

> *"List all imports of C:\malware\dropper.dll and flag anything dangerous"*

Claude will enumerate all DLLs and functions, then automatically flag:
- Process injection APIs (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`)
- Anti-debug APIs (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`)
- Network APIs (`WSAStartup`, `connect`, `send`)
- Crypto APIs (`CryptEncrypt`, `CryptGenRandom`)
- Direct NT syscalls (`NtQueryValueKey`, `NtOpenProcess`)

### Export Listing

> *"What functions does C:\tools\hook.dll export?"*

Lists all named exports with their ordinals — useful for understanding what a DLL exposes to callers.

### Binary Patching

> *"NOP out 6 bytes at offset 0x1234 in C:\crack\game.exe"*

> *"Invert the jump at file offset 0x5678 in C:\target\app.exe"*

> ⚠️ **Always back up files before patching.** These operations modify the file in-place.

### Resource Extraction

> *"Extract the manifest from C:\app\installer.exe and save it to C:\temp\manifest.xml"*

Common resource type IDs:

| Constant | ID | Description |
|---|---|---|
| `RT_CURSOR` | 1 | Hardware cursor |
| `RT_BITMAP` | 2 | Bitmap image |
| `RT_ICON` | 3 | Application icon |
| `RT_MENU` | 4 | Menu |
| `RT_DIALOG` | 5 | Dialog box |
| `RT_STRING` | 6 | String table |
| `RT_VERSION` | 16 | Version info |
| `RT_MANIFEST` | 24 | App manifest (XML) |

---

## Project Structure

```
cff-explorer-mcp/
│
├── server.py                        ← Main MCP server (all logic lives here)
├── requirements.txt                 ← Python dependencies (just: mcp)
├── .gitignore                       ← Standard Python/Windows gitignore
├── claude_desktop_config_example.json  ← Config template for Claude Desktop
└── README.md                        ← This file
```

### Inside `server.py`

| Section | Description |
|---------|-------------|
| `run_cff_script()` | Core runner — writes temp `.cff` file, invokes CFF Explorer subprocess, captures stdout |
| `script_*()` functions | Lua script generators for each tool — written for CFF Explorer's modified Lua |
| `parse_*()` functions | Parse CFF Explorer's stdout into clean Python dicts |
| `list_tools()` | MCP tool definitions (names, descriptions, JSON schemas) |
| `call_tool()` | MCP tool dispatch — routes calls to the right script + parser |

---

## CFF Explorer Scripting Notes

CFF Explorer uses a **modified Lua** dialect. Key differences from standard Lua that this project accounts for:

| Feature | Standard Lua | CFF Explorer Lua |
|---------|-------------|-----------------|
| Arrays | 1-based | 0-based |
| Not-equal | `~=` | `!=` |
| Null value | `nil` | `null` |
| Raw strings | N/A | `@"C:\path"` (C# style) |
| `os` library | Available | ❌ Not available |
| `io` library | Available | ❌ Not available |
| Output | `io.write()` | `print()` → stdout |

> The `os` and `io` libraries being absent was the main bug found during development. All scripts in this project use only `print()` for output.

---

## Troubleshooting

### Script times out
- Make sure **Scripting Privilege Protection (SPP)** is disabled in CFF Explorer preferences
- Check that `CFF_EXPLORER_PATH` points to the correct `.exe`
- Try running CFF Explorer manually first to ensure it opens

### "CFF Explorer not found" error
- Verify the path in your `claude_desktop_config.json`
- Default install path: `C:\Program Files\Explorer Suite\CFF Explorer.exe`
- Use double backslashes in JSON: `C:\\Program Files\\Explorer Suite\\CFF Explorer.exe`

### Tools not appearing in Claude Desktop
- Restart Claude Desktop completely after editing the config
- Validate your JSON (no trailing commas, balanced braces)
- Check Claude Desktop logs: `%APPDATA%\Claude\logs\`

### "attempt to index global 'os'" error
- You are running an old version of `server.py` — update to the latest version
- The old version incorrectly used `os.tmpname()` which doesn't exist in CFF Explorer's Lua

---

## Contributing

Pull requests are welcome! Some ideas for future tools:

- `check_packer` — detect common packers (UPX, Themida, etc.) by section entropy
- `update_checksum` — recalculate and write the PE checksum after patching
- `add_section` — add a new section to a PE file
- `realign_pe` — realign sections to a given alignment value
- `dotnet_metadata` — dump .NET metadata tables for managed assemblies

---

## Credits

- **CFF Explorer & Scripting Engine** — [Daniel Pistelli / NTCore](https://ntcore.com) — the tool that makes all of this possible
- **MCP SDK** — [Anthropic](https://github.com/anthropics/anthropic-sdk-python)
- **GhidraMCP** — [LaurieWired](https://github.com/LaurieWired/GhidraMCP) — inspiration for combining RE tools with MCP

---

*Built with Claude*