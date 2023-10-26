# YARA Rule Generator
This Python script extracts ASCII and Unicode strings from a Portable Executable (PE) file and generates YARA rules based on these strings. It also includes an option to detect and filter out gibberish strings.

## Prerequisites
Before using this tool, make sure you have the following prerequisites installed:

- PEfile
- Gibberish Detector

You can install these prerequisites using the following commands:

``pip install pefile``

``pip install gibberish_detector``

Or you can simply run 

`pip install -r requirements.txt`

## Usage
You can use this tool to extract strings from a PE file and generate YARA rules. The basic usage is as follows:

``python main.py <path_to_pe_file> <output_file> [-g] [-t] [-l]``


``<path_to_pe_file>``: The path to the PE file you want to analyze.

``<output_file>``: The path to the output file where the generated YARA rules will be saved.

``-g or --detect_gibberish``: Use this flag to enable gibberish detection and filtering. (Optional)

``-t or --threshold``: Specify the threshold for gibberish words (default is 4.2). Lower value is more strict checks. (Optional)

``-l or --min_length``: Specify the minimum length of strings to extract (default is 6). (Optional)

## Example
Here is an example of how to use the tool:

``python main.py malware.exe output.yar -g -t 5.1 -l 8``

In this example, the tool will analyze the "malware.exe" file, enable gibberish detection, and only extract strings with a minimum length of 8 characters. The generated YARA rules will be saved in the "output.yar" file.

## YARA Rules
The generated YARA rules are based on the extracted strings. The rules will have the format:
```
rule string_1
{
    strings:
        $string_1 = "example_string"
    condition:
        $string_1
}
```
You can use these rules with YARA to scan other files or processes for similar strings.

# Author
## Noman Nasir Minhas

If you have any questions or issues, please feel free to contact the author.

Disclaimer
This tool is for educational and research purposes only. Use it responsibly and in compliance with all applicable laws and regulations. The author is not responsible for any misuse or damage caused by this tool.
