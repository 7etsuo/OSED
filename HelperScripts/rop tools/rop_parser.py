from colorama import Fore, Style, init
import sys
import re


init(autoreset=True)


class ROGadgetParser:
    def __init__(self, output, bad_chars):
        self.bad_chars = bad_chars
        self.instructions = self.parse_output(output)

    def parse_output(self, output):
        lines = output.split('\n')
        parsed_lines = []

        for line in lines:
            match = re.match(r"0x([0-9a-fA-F]+):", line)
            if match:
                hex_value = int(match.group(1), 16)
                instruction = line[match.end():].strip()
                instruction = instruction.replace(';  (1 found)', '').strip()
                parsed_line = f"struct.pack('<L', {hex(hex_value)})  # {instruction}"
                parsed_lines.append(parsed_line)

        return parsed_lines

    def filter_instructions(self, exclude_bad_chars=True):
        filtered_instructions = []
        for instruction in self.instructions:
            has_bad_char = self.contains_bad_char(instruction, self.bad_chars)
            if exclude_bad_chars:
                if not has_bad_char:
                    filtered_instructions.append(instruction)
            else:
                if has_bad_char:
                    filtered_instructions.append(instruction)

        return filtered_instructions

    @staticmethod
    def contains_bad_char(s, bad_chars):
        for bad_char in bad_chars:
            if bad_char in s:
                return True
        return False


class Printer:
    def __init__(self, instructions):
        self.instructions = instructions

    def print_instructions(self, search_terms=None, exclude_duplicates=False):
        unique_instructions = set()
        for instruction in self.instructions:
            if search_terms is None or all(re.search(term.lower(), instruction.lower()) for term in search_terms):
                if exclude_duplicates:
                    instr = instruction.split('#')[-1].strip()
                    if instr not in unique_instructions:
                        unique_instructions.add(instr)
                        print(Fore.BLUE + instruction)
                else:
                    print(instruction)


class Menu:
    def __init__(self, printer):
        self.printer = printer

    @staticmethod
    def print_title():
        title = "Auto RoParser"
        email = "snowcra5h@icloud.com"
        title_length = len(title) + len(email) + 4
        separator = "=" * title_length

        print(Fore.CYAN + Style.BRIGHT + separator)
        print(Fore.CYAN + Style.BRIGHT + f"({email})".center(title_length))
        print(Fore.CYAN + Style.BRIGHT + title.center(title_length))
        print(Fore.CYAN + Style.BRIGHT + separator + Style.RESET_ALL)

    def main(self):

        while True:
            self.print_title()
            print(Fore.YELLOW + "Menu:")
            print(Fore.GREEN + "1. Search for specific instructions")
            print(Fore.GREEN + "2. Quit")
            choice = input(Fore.YELLOW + "Enter your choice: ")

            if choice == '1':
                search = input(
                    Fore.CYAN + "Enter the instructions to search for separated by '|': ")
                search_terms = [term.strip().replace('*', r'.*')
                                for term in search.split('|')]
                exclude_duplicates = input(
                    Fore.CYAN + "Do you want to exclude duplicates? (y/n): ").lower() == 'y'
                self.printer.print_instructions(
                    search_terms, exclude_duplicates)

            elif choice == '2':
                break

            else:
                print(Fore.RED + "Invalid choice. Please try again.")


if __name__ == "__main__":
    input_file = "rop.txt"

    with open(input_file, 'r') as f:
        output = f.read()

    bad_chars = []

    bad_char_selection = input(
        Fore.CYAN + "Do you want to enter bad characters (y/n): ").lower() == 'y'
    if bad_char_selection:
        bad_chars = input(
            Fore.CYAN + "Enter a list of bad chars delimited by a space \'00 09 0A 0B 0C 0D 20\' ..: ").lower().split()

    parser = ROGadgetParser(output, bad_chars)
    printer = Printer(parser.filter_instructions())
    menu = Menu(printer)
    menu.main()
