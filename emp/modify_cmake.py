import os
import re
# import argparse
def replace_text_in_file(file_path, old_text, new_text):
    with open(file_path, 'r') as file:
        filedata = file.read()

    newdata = filedata.replace(old_text, new_text)

    with open(file_path, 'w') as file:
        file.write(newdata)

if __name__ == "__main__":
    from argparse import ArgumentParser
    option = ArgumentParser()
    option.add_argument("--file", help="file path")
    args = option.parse_args()
    file = args.file
    replace_text_in_file(file, 'c++11', 'c++14')
