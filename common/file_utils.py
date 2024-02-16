def read_file_lines(file_path):
    lines = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                lines.append(line.strip())

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error reading file: {e}")

    return lines


def write_to_file(file_path, line_to_write):
    with open(file_path, 'a') as file:
        file.write(line_to_write + '\n')
