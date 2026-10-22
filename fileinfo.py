#!/usr/bin/env python3
"""SPOTTED | Static Windows PE analyzer. Never executes the target."""
import argparse
import datetime as dt
import hashlib
import math
import os
from pathlib import Path
import re
import sys

try:
    import pefile
except ImportError:
    print('[!] Missing dependency: pip install pefile', file=sys.stderr)
    sys.exit(2)


def utc(ts):
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return 'unavailable'


def entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in Counter(data).values())


def hashes(path):
    digests = {name: hashlib.new(name) for name in ('sha256', 'sha512', 'sha1', 'md5')}
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def safe_decode(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def analyze(path, max_strings):
    st = path.stat()
    hs = hashes(path)
    lines = [
        '=' * 76, 'SPOTTED | PE ANALYZER', 'Static executable intelligence report', '=' * 76,
        f'Generated (UTC): {dt.datetime.now(dt.timezone.utc).isoformat()}',
        f'Target: {path}', f'File size: {st.st_size:,} bytes ({st.st_size / 1048576:.2f} MiB)',
        f'Created (UTC): {utc(st.st_ctime)} (Windows filesystem metadata)',
        f'Modified (UTC): {utc(st.st_mtime)}', '',
        '[ HASHES ]',
        *[f'{k.upper():8}: {v}' for k, v in hs.items()], ''
    ]
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        lines.extend(['[ PE ANALYSIS ]', f'Not a valid PE file: {exc}', ''])
        pe = None
    except Exception as exc:
        lines.extend(['[ PE ANALYSIS ]', f'Unable to parse PE: {exc}', ''])
        pe = None
    if pe is not None:
        try:
            machine = pe.FILE_HEADER.Machine
            machine_names = {0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64'}
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            flags = {0x0040: 'ASLR / DYNAMIC_BASE', 0x0100: 'DEP / NX_COMPAT',
                     0x4000: 'CONTROL_FLOW_GUARD', 0x0020: 'HIGH_ENTROPY_VA'}
            lines.extend([
                '[ PE HEADERS ]', f'Machine: {machine_names.get(machine, "unknown")} (0x{machine:04X})',
                f'PE timestamp (UTC): {utc(pe.FILE_HEADER.TimeDateStamp)} (may be forged)',
                f'Linker version: {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}',
                f'Subsystem: {pe.OPTIONAL_HEADER.Subsystem}',
                f'Entry point RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}',
                f'Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:X}',
                f'Size of image: {pe.OPTIONAL_HEADER.SizeOfImage:,}',
                f'Size of headers: {pe.OPTIONAL_HEADER.SizeOfHeaders:,}',
                f'Sections: {pe.FILE_HEADER.NumberOfSections}',
                f'Characteristics: 0x{pe.FILE_HEADER.Characteristics:04X}',
                '', '[ SECURITY FLAGS ]',
                *[f'{name}: {"enabled" if dll_chars & flag else "not flagged"}' for flag, name in flags.items()],
                'Note: header flags do not prove runtime protection.', '',
                '[ SECTIONS ]'
            ])
            for sec in pe.sections:
                name = safe_decode(sec.Name).rstrip('\x00')
                lines.append(f'{name} | RVA=0x{sec.VirtualAddress:X} | raw={sec.SizeOfRawData:,} | '
                             f'virtual={sec.Misc_VirtualSize:,} | entropy={sec.get_entropy():.3f} | '
                             f'flags=0x{sec.Characteristics:08X}')
            lines.extend(['', '[ IMPORTS ]'])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    lines.append(f'DLL: {safe_decode(entry.dll)}')
                    for imp in entry.imports:
                        symbol = safe_decode(imp.name) if imp.name else f'ordinal:{imp.ordinal}'
                        lines.append(f'  {symbol}')
            else:
                lines.append('(none found)')
            lines.extend(['', '[ EXPORTS ]'])
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    lines.append(f'{safe_decode(exp.name) if exp.name else "(unnamed)"} | ordinal={exp.ordinal} | RVA=0x{exp.address:X}')
            else:
                lines.append('(none found)')
            lines.extend(['', '[ RESOURCES / VERSION ]'])
            if hasattr(pe, 'FileInfo'):
                for group in pe.FileInfo:
                    for item in group:
                        if hasattr(item, 'StringTable'):
                            for table in item.StringTable:
                                for k, v in table.entries.items():
                                    lines.append(f'{safe_decode(k)}: {safe_decode(v)}')
            else:
                lines.append('(no version info found)')
            lines.extend(['', '[ DIGITAL SIGNATURE ]'])
            cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            lines.append(f'Authenticode certificate table: {"present" if cert_dir.Size else "absent"} (size={cert_dir.Size})')
            lines.append('Signature trust/validity is NOT verified by this tool.')
            lines.extend(['', '[ OVERLAY ]'])
            overlay = pe.get_overlay()
            lines.append(f'Overlay bytes: {len(overlay) if overlay else 0:,}')
        except Exception as exc:
            lines.extend(['', f'[!] Partial PE parsing error: {exc}'])
        finally:
            pe.close()

    lines.extend(['', '[ STRINGS / INDICATORS ]', f'Maximum printed strings: {max_strings}'])
    # Stream through the file, retaining only a bounded number of strings.
    ascii_pat = re.compile(rb'[\x20-\x7e]{6,}')
    url_pat = re.compile(r'https?://[^\s\"\'<>]{3,}', re.I)
    ipv4_pat = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    printed = 0
    carry = b''
    with path.open('rb') as f:
        while printed < max_strings:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            data = carry + chunk
            matches = list(ascii_pat.finditer(data))
            carry = b''
            if matches and matches[-1].end() == len(data):
                carry = matches[-1].group()[-4096:]
                matches.pop()
            for match in matches:
                s = safe_decode(match.group()[:300])
                if url_pat.search(s) or ipv4_pat.search(s) or any(x in s.lower() for x in ('.dll', '.exe', 'http', 'powershell', 'cmd.exe', 'software\\')):
                    lines.append(s)
                    printed += 1
                    if printed >= max_strings:
                        break
    if not printed:
        lines.append('(no matching indicators found)')
    lines.extend(['', '[ NOTES ]',
                  'Static inspection only. Findings are not evidence of malicious behavior.',
                  'No executable code from the target was run.',
                  'SPOTTED | END OF REPORT'])
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='SPOTTED | Windows PE static analyzer')
    parser.add_argument('target', type=Path, help='Path to an EXE/DLL file')
    parser.add_argument('-o', '--output', type=Path, default=Path('dataexport.txt'))
    parser.add_argument('--max-strings', type=int, default=300)
    args = parser.parse_args()
    if not args.target.is_file():
        parser.error(f'file not found: {args.target}')
    if args.max_strings < 0 or args.max_strings > 10000:
        parser.error('--max-strings must be between 0 and 10000')
    target = args.target.resolve()
    output = args.output.resolve()
    if target == output:
        parser.error('output cannot overwrite target')
    report = analyze(target, args.max_strings)
    output.write_text(report, encoding='utf-8')
    print('[SPOTTED] Analysis complete')
    print(f'[+] SHA256: {hashlib.sha256(target.read_bytes()).hexdigest()}')
    print(f'[+] Report: {output}')


if __name__ == '__main__':
    main()
