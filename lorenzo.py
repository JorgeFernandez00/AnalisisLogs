import dataclasses
import datetime
import os.path
import re
from typing import Union, List, Dict, Type

LOG_DIR = 'hnet-hon-var-log-02282006'
MONTH = '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
DAY = '(Mon|Tue|Wed|Thu|Fri|Sat|Sun)'
DATE = '([0 ][1-9]|[12][0-9]|3[01])'
TIME = '([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]'


@dataclasses.dataclass
class Logs:
    priority: int = None
    protocol_ver: int = 1
    timestamp: Union[datetime.datetime, float] = None
    host_name: str = None
    app_name: str = None
    process_id: int = None
    message_id: str = None
    struct_data: Dict = dataclasses.field(default_factory=dict)
    message: str = None

    raw: str = None
    creation_time: float = None
    error: bool = False

    def __str__(self):
        if self.struct_data:
            struct_data = '[' + ' '.join([f'{key}="{value}"' for key, value in self.struct_data.items()]) + ']'
        else:
            struct_data = '-'

        # transform each None value to '-'
        for key, value in self.__dict__.items():
            if value is None:
                self.__dict__[key] = '-'

        return f'<{self.priority}>{self.protocol_ver} {self.timestamp:%Y-%m-%dT%H:%M:%S.%f+%z} {self.host_name} {self.app_name} {self.process_id} {self.message_id} {struct_data} {self.message}'


class UnixLogs(Logs):
    def __init__(self, raw: str):
        attributes = re.match(f'^(?P<timestamp>{MONTH} {DATE} {TIME}) (?P<host_name>\S+) (?:(?P<app_name>\S+)(?:\[(?P<process_id>\d+)\]): )?(?P<message>.*)$', raw).groupdict()
        # parse time
        attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%b %d %H:%M:%S').replace(year=datetime.datetime.now().year)
        super().__init__(**attributes, raw=raw)


def read_logs(log_file: str) -> List[str]:
    with open(log_file, 'r', encoding='utf8') as f:
        return [line for line in f]


def parse_logs(logs: List[str], parser_class: Type) -> List[Logs]:
    parsed_logs = []
    for log in logs:
        try:
            parsed_logs.append(parser_class(log))
        except AttributeError:
            print('AttributeError', log)
            continue
    return parsed_logs


# rules for parsing logs
rules = {
    r'boot.log(\.\d+)?': UnixLogs,
    r'cron(\.\d+)?': UnixLogs,
}


for root, dirs, files in os.walk(LOG_DIR):
    for file in files:
        # skip files with weird encoding or compressed files
        try:
            logs = read_logs(os.path.join(root, file))
        except UnicodeDecodeError:
            print('UnicodeDecodeError', os.path.join(root, file))
            continue

        for key in rules:
            if re.match(key, file):
                logs = parse_logs(logs, UnixLogs)
                break
        else:
            continue

        print(*logs, sep='\n')
