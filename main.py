import pefile
import argparse
import re
from gibberish_detector import detector

def extract_strings(pe, min_length=6):
    """
    Extracts all ASCII and Unicode strings from the PE file.
    """
    
    strings = []
    for section in pe.sections:
        s = section.get_data()
        ascii_strings = re.findall(b"[\x20-\x7E]{%d,}" % min_length, s)
        unicode_strings = re.findall(b"(?:[\x20-\x7E][\x00]){%d,}" % min_length, s)
        strings.extend(ascii_strings)
        strings.extend(unicode_strings)
    return strings

def generate_yara_rules(strings, detect_gibberish=False, threshold=4.2):
    """
    Generates yara rules for the extracted strings.
    """
    
    yara_rules = []
    Detector = False
    if detect_gibberish:
        Detector = detector.create_from_model('big.model')
    count = 0
    for string in strings:
        string = string.decode("utf-8", errors="ignore")
        gib = 6
        if detect_gibberish:
            gib = Detector.calculate_probability_of_being_gibberish(string)
        if (detect_gibberish and gib < threshold and gib != 0) or not detect_gibberish:            
            string = string.strip()
            print(f'[+] String: {string}')
            count += 1
            yara_rule = f"""
rule string_{count}
{{
    strings:
        $string_{count} = "{string}"
    condition:
        $string_{count}
}}
            """     
                   
            yara_rules.append(yara_rule)
    return yara_rules

def main():
    try:
        """
        Parses the command-line arguments, extracts strings from the PE file, and generates yara rules.
        """
        parser = argparse.ArgumentParser(description="Extracts strings from a PE file and generates yara rules.")
        parser.add_argument("pe_file", help="Path to the PE file.")
        parser.add_argument("output", help="Path to the output file.")
        parser.add_argument("-g", "--detect_gibberish", action="store_true", help="Detects gibberish strings.")
        parser.add_argument("-l", "--min_length", type=int, default=6, help="Minimum length of the string.")
        parser.add_argument("-t", "--threshold", type=float, default=4.2, help="Threshold for gibberish detection. Default is 4.2.")
        
        args = parser.parse_args()
        detect_gibberish = args.detect_gibberish
        min_length = args.min_length
        pe = pefile.PE(args.pe_file)
        output = args.output
        strings = extract_strings(pe, min_length)
        yara_rules = generate_yara_rules(strings, detect_gibberish, args.threshold)
        
        #Store generate yara rules in a file overwriting the previous one
        with open(output, "w") as f:
            for yara_rule in yara_rules:
                f.write(yara_rule + "\n")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
