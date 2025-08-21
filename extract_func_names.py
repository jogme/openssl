#!/usr/bin/env python3
import re
import sys

def extract_function_names(header_file_path):
    """
    Extract function names from a C header file, handling multi-line prototypes.
    Skips macros, typedefs, and comments.
    
    BUGS:
    - will falsely match function pointers
    """
    func_pattern = re.compile(
        r'^[\w\s\*\),]+\s+\*?(\w+)\s*\([^;]*\);',
        re.MULTILINE
    )

    functions = []
    buffer = ""

    with open(header_file_path, "r") as f:
        for line in f:
            # Skip obvious non-prototype lines
            if (line.strip().startswith("#")
                or line.strip().startswith("typedef")
                or line.strip().startswith("//")
                or line.strip().startswith("/*")):
                continue

            buffer += line.strip() + " "

            # If we see a semicolon, try matching as a whole prototype
            if ";" in line:
                match = func_pattern.match(buffer.strip())
                if match:
                    functions.append(match.group(1))
                buffer = ""  # reset for next function

    return functions

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <headerfile.h>")
        sys.exit(1)

    header_file = sys.argv[1]
    try:
        funcs = extract_function_names(header_file)
        if funcs:
            print("Functions found:")
            for fn in funcs:
                print(fn)
        else:
            print("No function declarations found.")
    except FileNotFoundError:
        print(f"Error: file '{header_file}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
