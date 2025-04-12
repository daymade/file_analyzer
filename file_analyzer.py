#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import binascii
import math
import re
import codecs
from collections import Counter
import glob

# --- Hex Viewer Logic (from hex_viewer.py) ---
def view_hex_data(file_path, num_bytes=256, bytes_per_line=16):
    """Displays hexadecimal data from the start, middle, and end of a file."""
    try:
        file_size = os.path.getsize(file_path)
        print(f"File size: {file_size} bytes\n")
        if file_size == 0:
            print("File is empty.")
            return

        with open(file_path, 'rb') as f:
            # Header
            print(f"--- File Header ({min(num_bytes, file_size)} bytes) ---")
            data = f.read(num_bytes)
            _print_hex_block(data, 0, bytes_per_line)

            # Middle (if file is large enough)
            if file_size > num_bytes * 2:
                middle_offset = (file_size // 2) - (num_bytes // 2)
                f.seek(middle_offset)
                print(f"\n--- File Middle ({num_bytes} bytes starting at offset {middle_offset}) ---")
                data = f.read(num_bytes)
                _print_hex_block(data, middle_offset, bytes_per_line)

            # Footer (if file has more data than header)
            if file_size > num_bytes:
                footer_offset = max(num_bytes, file_size - num_bytes)
                f.seek(footer_offset)
                print(f"\n--- File Footer ({min(num_bytes, file_size - footer_offset)} bytes starting at offset {footer_offset}) ---")
                data = f.read(num_bytes) # Read up to num_bytes
                _print_hex_block(data, footer_offset, bytes_per_line)

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred during hex view: {e}", file=sys.stderr)

def _print_hex_block(data, start_offset, bytes_per_line):
    for i in range(0, len(data), bytes_per_line):
        line_bytes = data[i:i+bytes_per_line]
        offset = start_offset + i
        hex_values = ' '.join(f'{b:02X}' for b in line_bytes)
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_bytes)
        print(f"{offset:08X}: {hex_values:<{bytes_per_line*3 - 1}} | {ascii_values}")

# --- Entropy Calculation Logic (from encoding_tester.py) ---
def calculate_entropy(data):
    """Calculates the Shannon entropy of a byte string."""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    byte_counts = Counter(data)
    for count in byte_counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

# --- Text Extraction Logic (from chinese_text_extractor.py and encoding_tester.py) ---
def find_potential_text_fragments(data, encoding='utf-8', min_len=4):
    """Finds potential text fragments using the specified encoding."""
    fragments = []
    current_fragment = bytearray()
    in_fragment = False
    null_byte = b'\x00'

    i = 0
    while i < len(data):
        found_char = False
        # Try decoding sequences of decreasing length (4, 3, 2, 1 bytes)
        for seq_len in range(min(4, len(data) - i), 0, -1):
            chunk = data[i:i+seq_len]
            # Avoid including null bytes in fragments initially
            if null_byte in chunk and seq_len > 1: # Allow single null byte if it decodes
                 continue
            try:
                decoded_char = chunk.decode(encoding, errors='strict')
                # Check if it's a meaningful character (e.g., not just whitespace or control char)
                # More robust checks could be added here (e.g., Unicode categories)
                if decoded_char.strip():
                    current_fragment.extend(chunk)
                    in_fragment = True
                    i += seq_len
                    found_char = True
                    break
            except UnicodeDecodeError:
                continue # Try shorter sequence

        if not found_char:
            # If we couldn't decode anything starting at i, end the current fragment
            if in_fragment and len(current_fragment) >= min_len:
                try:
                    fragments.append(current_fragment.decode(encoding, errors='ignore'))
                except: # Ignore fragments that still fail somehow
                    pass
            current_fragment = bytearray()
            in_fragment = False
            i += 1 # Move to the next byte

    # Add the last fragment if it's long enough
    if in_fragment and len(current_fragment) >= min_len:
         try:
            fragments.append(current_fragment.decode(encoding, errors='ignore'))
         except:
            pass

    return fragments

def extract_text(file_path, encodings=['utf-8', 'gb18030', 'gbk'], min_len=4, limit=10):
    """Attempts to extract text using multiple encodings."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if not data:
            print("File is empty.")
            return

        print(f"Attempting text extraction (min fragment length: {min_len})...")
        all_fragments = {}
        best_encoding = None
        max_fragments = 0

        for enc in encodings:
            try:
                print(f"\n--- Trying encoding: {enc} ---")
                fragments = find_potential_text_fragments(data, encoding=enc, min_len=min_len)
                all_fragments[enc] = fragments
                print(f"  Found {len(fragments)} potential fragments.")
                if fragments:
                    print(f"  First {limit} fragments:")
                    for i, frag in enumerate(fragments[:limit]):
                        print(f"    {i+1}: {frag[:100]}{'...' if len(frag)>100 else ''}") # Limit fragment display length
                if len(fragments) > max_fragments:
                    max_fragments = len(fragments)
                    best_encoding = enc
            except Exception as e:
                print(f"  Error processing encoding {enc}: {e}")

        if best_encoding:
            print(f"\nEncoding '{best_encoding}' yielded the most fragments ({max_fragments}).")
        else:
            print("\nNo text fragments found with the specified encodings.")

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred during text extraction: {e}", file=sys.stderr)

# --- BitLocker Detection Logic (from bitlocker_detector.py) ---
def check_bitlocker_signatures(file_path):
    """Checks for potential BitLocker signatures and related patterns."""
    signatures = {
        b'-FVE-FS-': 'BitLocker Signature', # Standard signature
        b'MSWIN4.1': 'Possible related artifact (older Windows)',
        # Add more potential signatures or patterns if known
    }
    found_signatures = []
    try:
        with open(file_path, 'rb') as f:
            # Read a reasonable chunk, e.g., first 1MB, signatures are usually near the start
            data = f.read(1024 * 1024)

        print("--- Checking for BitLocker Signatures ---")
        if not data:
            print("File is empty or could not be read.")
            return

        for sig, desc in signatures.items():
            if sig in data:
                offset = data.find(sig)
                found_signatures.append(f"'{desc}' found at offset {offset} (0x{offset:X})")

        if found_signatures:
            print("Potential BitLocker related signatures found:")
            for found in found_signatures:
                print(f"  - {found}")
        else:
            print("No common BitLocker signatures found in the first 1MB.")

        # Basic Entropy Check (as high entropy is common)
        entropy = calculate_entropy(data[:65536]) # Entropy on first 64k
        print(f"Entropy (first 64KB): {entropy:.4f}")
        if entropy > 7.5:
            print("High entropy detected, which *could* indicate encryption (like BitLocker) or compression.")
        elif entropy < 1.0:
             print("Very low entropy detected, suggesting highly repetitive data (unlikely for BitLocker volume).")
        else:
             print("Entropy is moderate.")

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred during BitLocker check: {e}", file=sys.stderr)

# --- Main Execution & Argument Parsing ---
def process_file(file_path, args):
    """Processes a single file based on the command."""
    if not os.path.isfile(file_path):
        print(f"Skipping non-file: {file_path}", file=sys.stderr)
        return
    
    print(f"\n=== Processing: {os.path.basename(file_path)} ({args.command}) ===")
    try:
        if args.command == 'analyze':
            extract_text(file_path, encodings=args.encodings, min_len=args.min_len, limit=args.limit)
            print("\n")
            check_bitlocker_signatures(file_path) # Includes entropy
        elif args.command == 'hexview':
            view_hex_data(file_path, num_bytes=args.bytes, bytes_per_line=args.line_bytes)
        elif args.command == 'extract-text':
            extract_text(file_path, encodings=args.encodings, min_len=args.min_len, limit=args.limit)
        elif args.command == 'check-bitlocker':
            check_bitlocker_signatures(file_path)
    except Exception as e:
         print(f"Error processing {file_path}: {e}", file=sys.stderr)
    print(f"=== Finished processing: {os.path.basename(file_path)} ===")


def main():
    parser = argparse.ArgumentParser(description="Analyze file contents (Hex, Text, Entropy, Signatures).")
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    # Common argument for file/directory paths
    path_help = 'Path(s) to file(s) or directory(ies) to analyze.'

    # --- Analyze Command ---
    parser_analyze = subparsers.add_parser('analyze', help='Perform general analysis (entropy, text fragments, BitLocker check).')
    parser_analyze.add_argument('paths', nargs='+', help=path_help)
    parser_analyze.add_argument('--encodings', nargs='+', default=['utf-8', 'gb18030', 'gbk', 'big5'], help='Encodings to try for text extraction.')
    parser_analyze.add_argument('--min-len', type=int, default=4, help='Minimum length for text fragments.')
    parser_analyze.add_argument('--limit', type=int, default=5, help='Max number of text fragments to display per encoding.')
    parser_analyze.add_argument('--recursive', action='store_true', help='Recursively search directories.')


    # --- Hexview Command ---
    parser_hexview = subparsers.add_parser('hexview', help='Display hexadecimal view of the file(s).')
    parser_hexview.add_argument('paths', nargs='+', help=path_help)
    parser_hexview.add_argument('--bytes', type=int, default=256, help='Number of bytes to display from header/middle/footer.')
    parser_hexview.add_argument('--line-bytes', type=int, default=16, help='Bytes per line in hex view.')
    parser_hexview.add_argument('--recursive', action='store_true', help='Recursively search directories.')

    # --- Extract-Text Command ---
    parser_extract = subparsers.add_parser('extract-text', help='Extract potential text fragments using specified encodings.')
    parser_extract.add_argument('paths', nargs='+', help=path_help)
    parser_extract.add_argument('--encodings', nargs='+', default=['utf-8', 'gb18030', 'gbk', 'big5', 'shift_jis'], help='Encodings to try.')
    parser_extract.add_argument('--min-len', type=int, default=4, help='Minimum length for text fragments.')
    parser_extract.add_argument('--limit', type=int, default=20, help='Max number of text fragments to display per encoding.')
    parser_extract.add_argument('--recursive', action='store_true', help='Recursively search directories.')


    # --- Check-Bitlocker Command ---
    parser_bitlocker = subparsers.add_parser('check-bitlocker', help='Check for BitLocker signatures and high entropy.')
    parser_bitlocker.add_argument('paths', nargs='+', help=path_help)
    parser_bitlocker.add_argument('--recursive', action='store_true', help='Recursively search directories.')


    args = parser.parse_args()

    files_to_process = []
    for path_arg in args.paths:
        if os.path.isfile(path_arg):
            files_to_process.append(path_arg)
        elif os.path.isdir(path_arg):
            search_path = os.path.join(path_arg, '**', '*') if args.recursive else os.path.join(path_arg, '*')
            found_files = glob.glob(search_path, recursive=args.recursive)
            # Filter found_files to include only actual files
            dir_files = [f for f in found_files if os.path.isfile(f)]
            files_to_process.extend(dir_files)
            print(f"Found {len(dir_files)} file(s) in directory '{path_arg}' (recursive={args.recursive}).")
        else:
            # Check if it's a glob pattern itself
            potential_files = glob.glob(path_arg)
            if potential_files:
                files_to_process.extend([f for f in potential_files if os.path.isfile(f)])
            else:
                 print(f"Warning: Path not found or not a file/directory: {path_arg}", file=sys.stderr)

    # Remove duplicates if paths/globs overlap
    files_to_process = sorted(list(set(files_to_process)))

    if not files_to_process:
         print("No valid files found to process.", file=sys.stderr)
         sys.exit(1)

    print(f"\nStarting processing for {len(files_to_process)} file(s)...")

    for file_path in files_to_process:
        process_file(file_path, args) # Pass args to the processing function

    print("\n=== All Processing Complete ===")


if __name__ == "__main__":
    main()
