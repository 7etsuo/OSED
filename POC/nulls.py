def removeNullChars(unsafe_to_use: hex, safe_to_use: hex) -> hex:
    value_to_add = unsafe_to_use - safe_to_use

    return value_to_add


def main():
    new_value = removeNullChars(0x1000, 0x41414141)
    old_val = new_value + 0x41414141

    print(old_val)


if __name__ == "__main__":
    main()
