from colorama import Fore, Style, init
import re

init(autoreset=True)


class UserInterface:
    @staticmethod
    def get_input(prompt):
        return input(Fore.CYAN + prompt)

    @staticmethod
    def print_message(message, color=Fore.YELLOW):
        print(color + message)

    @staticmethod
    def print_error(message):
        UserInterface.print_message(message, Fore.RED)

    @staticmethod
    def get_yes_no(prompt):
        return UserInterface.get_input(prompt).lower() == 'y'

    @staticmethod
    def get_search_terms():
        search = UserInterface.get_input("Enter the instructions to search for separated by '|': ")
        return [term.strip().replace('*', r'.*') for term in search.split('|')]

    @staticmethod
    def get_bad_chars():
        return UserInterface.get_input("Enter a list of bad chars delimited by a space \'00 09 0A 0B 0C 0D 20\' ..: ").lower().split()

class ROGadgetParser:
    def __init__(self, output, bad_chars, remove_base_address):
        self.bad_chars = bad_chars
        self.instructions = self.parse_output(output, remove_base_address)

    def parse_output(self, output, remove_base_address):
        lines = output.split('\n')
        parsed_lines = []

        for line in lines:
            match = re.match(r"0x([0-9a-fA-F]+):", line)
            if match:
                hex_value = int(match.group(1), 16)
                instruction = line[match.end():].strip()
                instruction = instruction.replace(';  (1 found)', '').strip()
                if remove_base_address:
                    parsed_line = f"struct.pack('<L', {hex(hex_value & 0xFFFFFF)})  # {instruction}"
                else:
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
        hex_str = re.search(r"struct.pack\(\'<L\', (0x[0-9a-fA-F]+)\)", s)
        if hex_str:
            hex_value = hex_str.group(1)
            hex_without_prefix = hex_str.group(1)[2:]
            hex_value = '0x' + (hex_without_prefix if len(hex_without_prefix) %
                                2 == 0 else '0' + hex_without_prefix)
            hex_bytes = bytes.fromhex(hex_value[2:])

            for bad_char in bad_chars:
                bad_char_byte = bytes.fromhex(bad_char)
                if bad_char_byte in hex_bytes:
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
                        UserInterface.print_message(Fore.BLUE + instruction)
                else:
                    UserInterface.print_message(instruction)


class Menu:
    def __init__(self, printer):
        self.printer = printer

    @staticmethod
    def print_title():
        title = "Auto RoParser"
        email = "snowcra5h@icloud.com"
        title_length = len(title) + len(email) + 4
        separator = "=" * title_length

        UserInterface.print_message(Fore.CYAN + Style.BRIGHT + separator)
        UserInterface.print_message(Fore.CYAN + Style.BRIGHT + f"({email})".center(title_length))
        UserInterface.print_message(Fore.CYAN + Style.BRIGHT + title.center(title_length))
        UserInterface.print_message(Fore.CYAN + Style.BRIGHT + separator + Style.RESET_ALL)

    def main(self):
        while True:
            self.print_title()
            UserInterface.print_message(Fore.YELLOW + "Menu:")
            UserInterface.print_message(Fore.GREEN + "1. Search for specific instructions")
            UserInterface.print_message(Fore.GREEN + "2. Quit")
            choice = UserInterface.get_input(Fore.YELLOW + "Enter your choice: ")

            if choice == '1':
                search = UserInterface.get_input(
                    Fore.CYAN + "Enter the instructions to search for separated by '|': ")
                search_terms = [term.strip().replace('*', r'.*')
                                for term in search.split('|')]
                exclude_duplicates = UserInterface.get_input(
                    Fore.CYAN + "Do you want to exclude duplicates? (y/n): ").lower() == 'y'
                self.printer.print_instructions(
                    search_terms, exclude_duplicates)

            elif choice == '2':
                break

            else:
                UserInterface.print_error(Fore.RED + "Invalid choice. Please try again.")


if __name__ == "__main__":

    bad_chars = []

    if UserInterface.get_yes_no("Do you want to enter bad characters (y/n): "):
        bad_chars = UserInterface.get_bad_chars()

    input_file = UserInterface.get_input("Enter the name of the file to parse: ")
    with open(input_file, 'r') as f:
        output = f.read()

    remove_base_address = UserInterface.get_yes_no("Do you want to remove the base address from the output (y/n): ")

    parser = ROGadgetParser(output, bad_chars, remove_base_address)
    printer = Printer(parser.filter_instructions())
    menu = Menu(printer)
    menu.main()
