import re
import gzip
import codecs
import base64
import sys

PREAMBLE_STR = "\x1B\[8mha:"  # regular expression
POSTAMBLE_STR = "\x1B\[0m"  # regular expression

log_file_path = sys.argv[1]
with open(log_file_path, "r", encoding="utf8") as fp:
    content = fp.readlines()

decode_lines = []
for line in content:
    line = line.strip()
    line_split = re.split("{}|{}".format(PREAMBLE_STR, POSTAMBLE_STR), line)
    if len(line_split) < 2:
        decode_lines.append(line)
        continue
    line_base64data = base64.b64decode(line_split[1])
    line_base64data = line_base64data[40:]
    extract = gzip.decompress(line_base64data)
    print("Original line: ")
    print("  {}".format(line))
    print("    Extracted line: ")
    print("      Part1: {} ".format(line_split[0]))
    print("      Part2: {} ".format(extract))
    print("      Part3: {} ".format(line_split[2].strip()))
    decode_lines.append(f"{line_split[0]}{extract}{line_split[2]}")

with open(log_file_path+".txt", "w", encoding="utf8", newline="") as fp:
    fp.writelines("\n".join(decode_lines))