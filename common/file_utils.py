import os


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


def write_line_to_file(file_path, line_to_write):
    with open(file_path, 'a') as file:
        file.write(line_to_write + '\n')

def write_lines_to_file(file_path, lines_array):
    with open(file_path, 'a') as file:
        for line in lines_array:
            file.write(line + '\n')

def is_file_exists(file_path):
    return os.path.exists(file_path)