from datetime import datetime


def is_valid_datetime(date_string, date_format='%Y-%m-%d %H:%M:%S'):
    try:
        datetime.strptime(date_string, date_format)
        return True
    except ValueError:
        return False


def get_datetime_from_str(date_string, date_format='%Y-%m-%d %H:%M:%S'):
    return datetime.strptime(date_string, date_format)


def get_datetime_from_ts(ts_string):
    return datetime.fromtimestamp(int(ts_string))


def get_date_string(my_datetime: datetime):
    return my_datetime.strftime("%Y-%m-%d %H:%M:%S")


def get_timestamp_string(my_datetime: datetime):
    return str(int(my_datetime.timestamp()))
