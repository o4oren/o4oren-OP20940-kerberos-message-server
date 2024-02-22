def extract_substring_between(input_string, start_substring, end_substring):
    start_index = input_string.find(start_substring)
    end_index = input_string.find(end_substring, start_index + len(start_substring))

    if start_index != -1 and end_index != -1:
        substring = input_string[start_index + len(start_substring):end_index]
        return substring
    else:
        return None