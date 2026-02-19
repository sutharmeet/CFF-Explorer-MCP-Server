"""
CFF Explorer MCP Server
=======================
Bridges CFF Explorer's built-in Lua scripting CLI with the Model Context Protocol (MCP),
allowing Claude (or any MCP client) to perform PE file analysis and patching
entirely through natural language — powered by CFF Explorer running headlessly
in the background.

How it works:
  1. Claude calls a tool (e.g. analyze_pe_headers)
  2. This server generates a temporary .cff Lua script
  3. CFF Explorer.exe is launched as a subprocess with the script
  4. CFF Explorer runs silently, prints results to stdout, then exits
  5. This server parses the output and returns structured JSON to Claude
License: MIT
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Configuration ─────────────────────────────────────────────────────────────
# Override via environment variable CFF_EXPLORER_PATH if installed elsewhere.
CFF_EXPLORER_PATH = os.environ.get(
    "CFF_EXPLORER_PATH",
    r"C:\Program Files\Explorer Suite\CFF Explorer.exe"
)

app = Server("cff-explorer-mcp")


# ── Core Script Runner ────────────────────────────────────────────────────────

def run_cff_script(script_content: str, timeout: int = 30) -> dict:
    """
    Write a Lua script to a temporary .cff file and execute it via CFF Explorer.

    CFF Explorer supports a headless scripting mode: when launched with a .cff
    script file as its argument, it runs the script silently with no GUI window,
    prints any output to stdout, and exits. This function captures that output.

    Args:
        script_content: Lua script string using CFF Explorer's scripting API.
        timeout:        Maximum seconds to wait for CFF Explorer to finish.

    Returns:
        dict with keys:
            success (bool)  - True if returncode == 0
            output  (str)   - Captured stdout
            error   (str)   - Captured stderr or exception message
    """
    if not Path(CFF_EXPLORER_PATH).exists():
        return {
            "success": False,
            "output": "",
            "error": (
                f"CFF Explorer not found at: {CFF_EXPLORER_PATH}\n"
                f"Set the CFF_EXPLORER_PATH environment variable to the correct path.\n"
                f"Download CFF Explorer: https://ntcore.com/?page_id=388"
            )
        }

    # Write the script to a temp file with .cff extension
    with tempfile.NamedTemporaryFile(
        suffix=".cff", mode="w", delete=False, encoding="utf-8"
    ) as f:
        f.write(script_content)
        script_path = f.name

    try:
        result = subprocess.run(
            [CFF_EXPLORER_PATH, script_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "output": result.stdout.strip(),
            "error": result.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "error": f"Script timed out after {timeout}s."}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


# ── Lua Script Templates ──────────────────────────────────────────────────────
# Important notes about CFF Explorer's modified Lua:
#   - Standard Lua libraries (os, io) are NOT available
#   - Use print() for all output — it goes to stdout
#   - Arrays are 0-based (not standard Lua 1-based)
#   - Use != instead of ~= for not-equal
#   - null instead of nil
#   - C-style @ prefix for raw strings: @"C:\path\file"
#   - No 'local' keyword needed (and can cause issues inside loops)

def script_pe_header_analysis(file_path: str) -> str:
    """Generate Lua script to extract full PE header information."""
    fp = file_path.replace("\\", "\\\\")
    return f"""
-- PE Header Analysis Script
-- Reads DOS header, File header, Optional header and section table
-- All output via print() captured as stdout

pehandle = OpenFile(@"{fp}")
if pehandle == null then
    print("ERROR=Could not open file")
    return
end

-- PE type flags
is64     = IsPE64(pehandle)
isDotNet = IsDotNET(pehandle)
print("is_pe64="   .. tostring(is64))
print("is_dotnet=" .. tostring(isDotNet))

-- DOS Header (offset 0 from file start)
dosOffset = GetOffset(pehandle, PE_DosHeader)
if dosOffset != null then
    magic = ReadWord(pehandle, dosOffset)
    print("dos_magic=0x" .. string.format("%04X", magic))
end

-- COFF File Header
fileHeaderOffset = GetOffset(pehandle, PE_FileHeader)
if fileHeaderOffset != null then
    machine         = ReadWord(pehandle,  fileHeaderOffset)
    numSections     = ReadWord(pehandle,  fileHeaderOffset + 2)
    timestamp       = ReadDword(pehandle, fileHeaderOffset + 4)
    characteristics = ReadWord(pehandle,  fileHeaderOffset + 18)
    print("machine=0x"         .. string.format("%04X", machine))
    print("num_sections="      .. numSections)
    print("timestamp="         .. timestamp)
    print("characteristics=0x" .. string.format("%04X", characteristics))
end

-- Optional Header
optOffset = GetOffset(pehandle, PE_OptionalHeader)
if optOffset != null then
    magic2      = ReadWord(pehandle,  optOffset)
    entryPoint  = ReadDword(pehandle, optOffset + 0x10)
    imageBase32 = ReadDword(pehandle, optOffset + 0x18)
    sizeOfImage = ReadDword(pehandle, optOffset + 0x38)
    subsystem   = ReadWord(pehandle,  optOffset + 0x44)
    print("optional_magic=0x"  .. string.format("%04X", magic2))
    print("entry_point=0x"     .. string.format("%08X", entryPoint))
    print("image_base=0x"      .. string.format("%08X", imageBase32))
    print("size_of_image=0x"   .. string.format("%08X", sizeOfImage))
    print("subsystem="         .. subsystem)
end

-- Section Table (each IMAGE_SECTION_HEADER is 40 bytes)
nSections  = GetNumberOfSections(pehandle)
sectOffset = GetOffset(pehandle, PE_SectionHeaders)
if sectOffset != null and nSections != null then
    for i = 0, nSections - 1 do
        base    = sectOffset + (i * 40)
        secname = ReadString(pehandle, base)
        vsize   = ReadDword(pehandle, base + 8)
        rva     = ReadDword(pehandle, base + 12)
        rawsize = ReadDword(pehandle, base + 16)
        rawoff  = ReadDword(pehandle, base + 20)
        chars   = ReadDword(pehandle, base + 36)
        print("section_" .. i .. "=name:"    .. (secname or "?") ..
              ",vsize:0x"   .. string.format("%X", vsize)   ..
              ",rva:0x"     .. string.format("%X", rva)     ..
              ",rawsize:0x" .. string.format("%X", rawsize) ..
              ",rawoff:0x"  .. string.format("%X", rawoff)  ..
              ",chars:0x"   .. string.format("%X", chars))
    end
end

CloseHandle(pehandle)
"""


def script_list_imports(file_path: str) -> str:
    """Generate Lua script to walk the PE Import Directory and list all DLLs/functions."""
    fp = file_path.replace("\\", "\\\\")
    return f"""
-- Import Directory Listing Script
-- Walks IMAGE_IMPORT_DESCRIPTOR array and resolves function names

pehandle = OpenFile(@"{fp}")
if pehandle == null then
    print("ERROR: cannot open file")
    return
end

itOffset = GetOffset(pehandle, PE_ImportDirectory)
if itOffset == null then
    print("NO_IMPORTS")
    return
end

ImportDescriptorSize = 20
nDesc      = 0
FirstThunk = ReadDword(pehandle, itOffset + 16)

while FirstThunk != 0 do
    nameRva = ReadDword(pehandle, itOffset + (nDesc * ImportDescriptorSize) + 12)
    nameOff = RvaToOffset(pehandle, nameRva)
    modName = ReadString(pehandle, nameOff)
    print("DLL:" .. (modName or "?"))

    OFTs = ReadDword(pehandle, itOffset + (nDesc * ImportDescriptorSize))
    if OFTs != 0 then
        Thunks = RvaToOffset(pehandle, OFTs)
    else
        FTRva  = ReadDword(pehandle, itOffset + (nDesc * ImportDescriptorSize) + 16)
        Thunks = RvaToOffset(pehandle, FTRva)
    end

    bPE64    = IsPE64(pehandle)
    curOff   = Thunks

    if bPE64 == true then
        curThunk = ReadQword(pehandle, curOff)
    else
        curThunk = ReadDword(pehandle, curOff)
    end

    while curThunk != null and curThunk != 0 do
        isOrd = false
        if bPE64 == true then
            isOrd = (curThunk & IMAGE_ORDINAL_FLAG64) == IMAGE_ORDINAL_FLAG64
        else
            isOrd = (curThunk & IMAGE_ORDINAL_FLAG32) == IMAGE_ORDINAL_FLAG32
        end

        if isOrd == true then
            ordVal = ReadWord(pehandle, curOff)
            print("  FUNC:ordinal=0x" .. string.format("%04X", ordVal))
        else
            funcOff = RvaToOffset(pehandle, (curThunk & 0xFFFFFFFF))
            if funcOff != null then
                ordVal2 = ReadWord(pehandle, funcOff)
                fname   = ReadString(pehandle, funcOff + 2)
                print("  FUNC:ordinal=0x" .. string.format("%04X", ordVal2) .. ",name=" .. (fname or "?"))
            end
        end

        if bPE64 == true then
            curOff   = curOff + 8
            curThunk = ReadQword(pehandle, curOff)
        else
            curOff   = curOff + 4
            curThunk = ReadDword(pehandle, curOff)
        end
    end

    nDesc      = nDesc + 1
    FirstThunk = ReadDword(pehandle, itOffset + (nDesc * ImportDescriptorSize) + 16)
end

CloseHandle(pehandle)
"""


def script_list_exports(file_path: str) -> str:
    """Generate Lua script to walk the PE Export Directory and list all exported symbols."""
    fp = file_path.replace("\\", "\\\\")
    return f"""
-- Export Directory Listing Script
-- Reads IMAGE_EXPORT_DIRECTORY and resolves all named exports

pehandle = OpenFile(@"{fp}")
if pehandle == null then
    print("ERROR: cannot open file")
    return
end

expOffset = GetOffset(pehandle, PE_ExportDirectory)
if expOffset == null then
    print("NO_EXPORTS")
    return
end

nameRva  = ReadDword(pehandle, expOffset + 12)
base     = ReadDword(pehandle, expOffset + 16)
numFuncs = ReadDword(pehandle, expOffset + 20)
numNames = ReadDword(pehandle, expOffset + 24)
namesRva = ReadDword(pehandle, expOffset + 32)
ordsRva  = ReadDword(pehandle, expOffset + 36)

nameOff = RvaToOffset(pehandle, nameRva)
dllName = ReadString(pehandle, nameOff)
print("DLL_NAME:"      .. (dllName or "?"))
print("NUM_FUNCTIONS:" .. numFuncs)
print("NUM_NAMES:"     .. numNames)
print("ORDINAL_BASE:"  .. base)

namesOff = RvaToOffset(pehandle, namesRva)
ordsOff  = RvaToOffset(pehandle, ordsRva)

for i = 0, numNames - 1 do
    fnRva  = ReadDword(pehandle, namesOff + (i * 4))
    fnOff  = RvaToOffset(pehandle, fnRva)
    fname  = ReadString(pehandle, fnOff)
    ordVal = ReadWord(pehandle, ordsOff + (i * 2))
    print("EXPORT:ordinal=" .. (ordVal + base) .. ",name=" .. (fname or "?"))
end

CloseHandle(pehandle)
"""


def script_nop_bytes(file_path: str, offset: int, length: int) -> str:
    """Generate Lua script to NOP out bytes at a given file offset."""
    fp = file_path.replace("\\", "\\\\")
    return f"""
-- NOP Bytes Script
-- Overwrites {length} bytes at file offset 0x{offset:X} with NOP instructions

pehandle = OpenFile(@"{fp}")
if pehandle == null then
    print("ERROR: cannot open file")
    return
end

result = NopBytes(pehandle, {offset}, {length})
if result == true then
    SaveFile(pehandle)
    print("SUCCESS: NOPed {length} bytes at offset 0x{offset:X}")
else
    print("ERROR: NopBytes failed at offset 0x{offset:X}")
end

CloseHandle(pehandle)
"""


def script_invert_jump(file_path: str, offset: int) -> str:
    """Generate Lua script to invert a conditional jump at a given file offset."""
    fp = file_path.replace("\\", "\\\\")
    return f"""
-- Invert Jump Script
-- Inverts the conditional jump at file offset 0x{offset:X}
-- e.g. JZ (74) becomes JNZ (75), JE becomes JNE, etc.

pehandle = OpenFile(@"{fp}")
if pehandle == null then
    print("ERROR: cannot open file")
    return
end

result = InvertJump(pehandle, {offset})
if result == true then
    SaveFile(pehandle)
    print("SUCCESS: Inverted jump at offset 0x{offset:X}")
else
    print("ERROR: InvertJump failed - offset 0x{offset:X} may not be a conditional jump")
end

CloseHandle(pehandle)
"""


def script_save_resource(file_path: str, res_type: int, res_id: int, out_path: str) -> str:
    """Generate Lua script to extract a PE resource to disk."""
    fp = file_path.replace("\\", "\\\\")
    op = out_path.replace("\\", "\\\\")
    return f"""
-- Extract Resource Script
-- Saves resource (type={res_type}, id={res_id}) to disk

pehandle = OpenFile(@"{fp}")
if pehandle == null then
    print("ERROR: cannot open file")
    return
end

result = SaveResource(pehandle, @"{op}", {res_type}, {res_id})
if result == true then
    print("SUCCESS: Resource saved to {out_path}")
else
    print("ERROR: Could not extract resource type={res_type} id={res_id}")
end

CloseHandle(pehandle)
"""


# ── Output Parsers ────────────────────────────────────────────────────────────

def parse_pe_header_output(raw: str) -> dict:
    """Parse key=value lines from PE header script stdout into a structured dict."""
    result = {"sections": []}
    section_map = {}

    MACHINE_NAMES = {
        0x014C: "x86 (I386)",
        0x8664: "x64 (AMD64)",
        0x0200: "IA64",
        0x01C4: "ARM Thumb-2",
        0xAA64: "ARM64",
    }
    SUBSYSTEM_NAMES = {
        1:  "Native",
        2:  "Windows GUI",
        3:  "Windows CUI (Console)",
        5:  "OS/2 CUI",
        7:  "POSIX CUI",
        9:  "Windows CE GUI",
        10: "EFI Application",
        14: "Xbox",
        16: "Boot Application",
    }

    for line in raw.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")

        if key.startswith("section_"):
            idx = int(key.split("_")[1])
            parts = dict(p.split(":", 1) for p in val.split(",") if ":" in p)
            section_map[idx] = parts
            continue

        if   key == "is_pe64":        result["is_pe64"]        = val == "true"
        elif key == "is_dotnet":       result["is_dotnet"]      = val == "true"
        elif key == "dos_magic":       result["dos_magic"]      = val
        elif key == "machine":
            m = int(val, 16)
            result["machine"]      = val
            result["machine_name"] = MACHINE_NAMES.get(m, "Unknown")
        elif key == "num_sections":    result["num_sections"]   = int(val)
        elif key == "timestamp":       result["timestamp"]      = int(val)
        elif key == "characteristics": result["characteristics"]= val
        elif key == "optional_magic":  result["optional_magic"] = val
        elif key == "entry_point":     result["entry_point"]    = val
        elif key == "image_base":      result["image_base"]     = val
        elif key == "size_of_image":   result["size_of_image"]  = val
        elif key == "subsystem":
            s = int(val)
            result["subsystem"]      = s
            result["subsystem_name"] = SUBSYSTEM_NAMES.get(s, "Unknown")

    result["sections"] = [section_map[i] for i in sorted(section_map)]
    return result


def parse_imports_output(raw: str) -> list:
    """Parse import listing stdout into a structured list of DLL + function dicts."""
    imports = []
    current_dll = None

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("DLL:"):
            current_dll = {"dll": line[4:], "functions": []}
            imports.append(current_dll)
        elif line.startswith("FUNC:") and current_dll:
            parts = dict(p.split("=", 1) for p in line[5:].split(",") if "=" in p)
            current_dll["functions"].append(parts)
        elif line in ("NO_IMPORTS", "ERROR: cannot open file"):
            return []

    return imports


def parse_exports_output(raw: str) -> dict:
    """Parse export listing stdout into a structured dict."""
    result = {
        "dll_name": "",
        "num_functions": 0,
        "num_names": 0,
        "ordinal_base": 0,
        "exports": []
    }

    for line in raw.splitlines():
        line = line.strip()
        if   line.startswith("DLL_NAME:"):      result["dll_name"]      = line[9:]
        elif line.startswith("NUM_FUNCTIONS:"): result["num_functions"]  = int(line[14:])
        elif line.startswith("NUM_NAMES:"):     result["num_names"]      = int(line[10:])
        elif line.startswith("ORDINAL_BASE:"):  result["ordinal_base"]   = int(line[13:])
        elif line.startswith("EXPORT:"):
            parts = dict(p.split("=", 1) for p in line[7:].split(",") if "=" in p)
            result["exports"].append(parts)

    return result


# ── MCP Tool Definitions ──────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="analyze_pe_headers",
            description=(
                "Analyze the PE (Portable Executable) headers of a file using CFF Explorer. "
                "Returns DOS header, File header, Optional header, and full section table."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full Windows path to the PE file (e.g. C:\\\\samples\\\\malware.exe)"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="list_imports",
            description=(
                "List all imported DLLs and their functions from a PE file using CFF Explorer. "
                "Useful for identifying suspicious API usage in binaries (e.g. VirtualAlloc, WriteProcessMemory)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full Windows path to the PE file"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="list_exports",
            description=(
                "List all exported functions from a PE file (typically DLLs) using CFF Explorer."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full Windows path to the PE file"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="nop_bytes",
            description=(
                "NOP out (neutralize) a specified number of bytes at a given file offset in a PE file. "
                "Modifies the file in-place using CFF Explorer. Always back up the file first."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full Windows path to the PE file"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "File offset (decimal) where NOP patching begins"
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to NOP out"
                    }
                },
                "required": ["file_path", "offset", "length"]
            }
        ),
        Tool(
            name="invert_jump",
            description=(
                "Invert a conditional jump instruction at a given file offset in a PE file using CFF Explorer. "
                "For example: JZ (jump if zero) becomes JNZ (jump if not zero). "
                "Modifies the file in-place. Always back up the file first."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full Windows path to the PE file"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "File offset (decimal) of the conditional jump instruction"
                    }
                },
                "required": ["file_path", "offset"]
            }
        ),
        Tool(
            name="extract_resource",
            description=(
                "Extract a resource from a PE file to disk using CFF Explorer. "
                "Common resource type IDs: RT_ICON=3, RT_BITMAP=2, RT_MANIFEST=24, RT_VERSION=16, "
                "RT_DIALOG=5, RT_STRING=6, RT_MENU=4."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full Windows path to the PE file"
                    },
                    "resource_type": {
                        "type": "integer",
                        "description": "Resource type ID (e.g. 24 for RT_MANIFEST, 3 for RT_ICON)"
                    },
                    "resource_id": {
                        "type": "integer",
                        "description": "Resource ID number"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Full Windows path where the extracted resource will be saved"
                    }
                },
                "required": ["file_path", "resource_type", "resource_id", "output_path"]
            }
        ),
    ]


# ── MCP Tool Handlers ─────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:

    def respond(data: Any) -> list[TextContent]:
        return [TextContent(type="text", text=json.dumps(data, indent=2))]

    if name == "analyze_pe_headers":
        file_path = arguments["file_path"]
        result    = run_cff_script(script_pe_header_analysis(file_path))
        if not result["success"] and not result["output"]:
            return respond({"error": result["error"]})
        parsed = parse_pe_header_output(result["output"])
        parsed["file"] = file_path
        if result["error"]:
            parsed["warnings"] = result["error"]
        return respond(parsed)

    elif name == "list_imports":
        file_path = arguments["file_path"]
        result    = run_cff_script(script_list_imports(file_path))
        if not result["success"] and not result["output"]:
            return respond({"error": result["error"]})
        imports = parse_imports_output(result["output"])
        return respond({
            "file":            file_path,
            "total_dlls":      len(imports),
            "total_functions": sum(len(d["functions"]) for d in imports),
            "imports":         imports
        })

    elif name == "list_exports":
        file_path = arguments["file_path"]
        result    = run_cff_script(script_list_exports(file_path))
        if not result["success"] and not result["output"]:
            return respond({"error": result["error"]})
        exports = parse_exports_output(result["output"])
        exports["file"] = file_path
        return respond(exports)

    elif name == "nop_bytes":
        file_path = arguments["file_path"]
        offset    = arguments["offset"]
        length    = arguments["length"]
        result    = run_cff_script(script_nop_bytes(file_path, offset, length))
        return respond({
            "file":      file_path,
            "operation": "nop_bytes",
            "offset":    hex(offset),
            "length":    length,
            "success":   "SUCCESS" in result["output"],
            "message":   result["output"] or result["error"]
        })

    elif name == "invert_jump":
        file_path = arguments["file_path"]
        offset    = arguments["offset"]
        result    = run_cff_script(script_invert_jump(file_path, offset))
        return respond({
            "file":      file_path,
            "operation": "invert_jump",
            "offset":    hex(offset),
            "success":   "SUCCESS" in result["output"],
            "message":   result["output"] or result["error"]
        })

    elif name == "extract_resource":
        file_path = arguments["file_path"]
        res_type  = arguments["resource_type"]
        res_id    = arguments["resource_id"]
        out_path  = arguments["output_path"]
        result    = run_cff_script(script_save_resource(file_path, res_type, res_id, out_path))
        return respond({
            "file":          file_path,
            "resource_type": res_type,
            "resource_id":   res_id,
            "output_path":   out_path,
            "success":       "SUCCESS" in result["output"],
            "message":       result["output"] or result["error"]
        })

    else:
        return respond({"error": f"Unknown tool: {name}"})


# ── Entry Point ───────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())