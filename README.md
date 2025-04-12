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
python file_analyzer.py <command> <file_path> [options]
```

### Commands

*   `analyze <file_path> [options]`: 
    Performs general analysis (entropy, text fragments, BitLocker check).
    *   `--encodings <enc1> <enc2> ...`: Specify encodings to try (default: utf-8 gb18030 gbk big5).
    *   `--min-len <length>`: Minimum length for text fragments (default: 4).
    *   `--limit <number>`: Max fragments to show per encoding (default: 5).

*   `hexview <file_path> [options]`: 
    Displays hexadecimal view.
    *   `--bytes <num>`: Bytes to show from header/middle/footer (default: 256).
    *   `--line-bytes <num>`: Bytes per line in hex view (default: 16).

*   `extract-text <file_path> [options]`: 
    Extracts potential text fragments.
    *   `--encodings <enc1> <enc2> ...`: Specify encodings (default: utf-8 gb18030 gbk big5 shift_jis).
    *   `--min-len <length>`: Minimum length for fragments (default: 4).
    *   `--limit <number>`: Max fragments to show per encoding (default: 20).

*   `check-bitlocker <file_path>`: 
    Checks for BitLocker signatures and high entropy.

### Examples

```bash
# Perform general analysis on a file
python file_analyzer.py analyze recovered_file.dat

# View hex data of a file
python file_analyzer.py hexview image.jpg --bytes 512

# Extract text using only GBK and GB18030
python file_analyzer.py extract-text document.unknown --encodings gbk gb18030

# Check for BitLocker signatures
python file_analyzer.py check-bitlocker partition.img
```

## Requirements

*   Python 3.x
*   No external libraries required by default.
