# File Analyzer Tool

A command-line tool to analyze file contents, useful for investigating potentially corrupted or unknown file formats.

## Features

*   **Hex Viewer:** Displays hexadecimal dumps of the file's header, middle, and footer.
*   **Text Extractor:** Attempts to extract readable text fragments using various common encodings (UTF-8, GB18030, GBK, Big5, Shift_JIS).
*   **Entropy Calculation:** Calculates Shannon entropy, which can indicate compression or encryption.
*   **BitLocker Check:** Looks for common BitLocker signatures and checks for high entropy.
*   **General Analysis:** Combines text extraction, BitLocker check, and entropy analysis.

## Usage

```bash
python file_analyzer.py <command> <path> [path...] [options]
```

### Arguments

*   `<path> [path...]`: One or more paths to files or directories to analyze.

### Commands

*   `analyze <path> [path...] [options]`:
    Performs general analysis (entropy, text fragments, BitLocker check).
    *   `--encodings <enc1> <enc2> ...`: Specify encodings to try (default: utf-8 gb18030 gbk big5).
    *   `--min-len <length>`: Minimum length for text fragments (default: 4).
    *   `--limit <number>`: Max fragments to show per encoding (default: 5).
    *   `--recursive`: Recursively search directories for files to analyze.

*   `hexview <path> [path...] [options]`:
    Displays hexadecimal view.
    *   `--bytes <num>`: Bytes to show from header/middle/footer (default: 256).
    *   `--line-bytes <num>`: Bytes per line in hex view (default: 16).
    *   `--recursive`: Recursively search directories for files to view.

*   `extract-text <path> [path...] [options]`:
    Extracts potential text fragments.
    *   `--encodings <enc1> <enc2> ...`: Specify encodings (default: utf-8 gb18030 gbk big5 shift_jis).
    *   `--min-len <length>`: Minimum length for fragments (default: 4).
    *   `--limit <number>`: Max fragments to show per encoding (default: 20).
    *   `--recursive`: Recursively search directories for files to extract text from.

*   `check-bitlocker <path> [path...] [options]`:
    Checks for BitLocker signatures and high entropy.
    *   `--recursive`: Recursively search directories for files to check.

### Examples

```bash
# Perform general analysis on a single file
python file_analyzer.py analyze recovered_file.dat

# Analyze all files directly inside the 'data' directory
python file_analyzer.py analyze data/

# Recursively analyze all files within the 'project_files' directory
python file_analyzer.py analyze project_files/ --recursive

# Analyze specific files
python file_analyzer.py analyze file1.bin file2.tmp ../other_dir/file3.dat

# View hex data of specific files
python file_analyzer.py hexview image.jpg doc.unknown

# Extract text using only GBK and GB18030 from all files in current dir
python file_analyzer.py extract-text . --encodings gbk gb18030

# Recursively check for BitLocker signatures in a directory
python file_analyzer.py check-bitlocker /mnt/partition --recursive

## Requirements

*   Python 3.x
*   No external libraries required by default.
