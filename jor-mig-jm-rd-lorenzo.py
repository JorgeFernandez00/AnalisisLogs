import dataclasses
import datetime 
import os.path
import re
from typing import Union, List, Dict, Type
from datetime import timezone

LOG_DIR = 'hnet-hon-var-log-02282006/var/log/'
MONTH = '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
DAY = '(Mon|Tue|Wed|Thu|Fri|Sat|Sun)'
DATE = '([0 ][1-9]|[12][0-9]|3[01])'
YEAR = '([1][0-9]{3}|[2][0-9]{3})'
TIME = '([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]'
NUMBER = '([0-9]{4})'
DESCRIPTION = '[a-z0-9\s:\"/\,\.\-]+'


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
        attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%b %d %H:%M:%S').replace(year=datetime.datetime.now().year).replace(tzinfo=datetime.timezone.utc)
        super().__init__(**attributes, raw=raw)

class SquidLogs(Logs):  
    def __init__(self, raw: str):

        accessExpresion = r'^(?P<timestamp>\d+\.\d+)\s+(?P<time>\d+)\s+(?P<host_name>\S+)\s+(?P<message>.*)$'  
        cacheExpresion = r'^(?P<timestamp>^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\|\s(?P<message>.*)$'
        refererExpresion = r'^(?P<timestamp>\d+\.\d+)\s(?P<host_name>\S+)\s(?P<message>(http|https).*)$'
        useragentExpresion = r'^(?P<host_name>\S+)\s+\[(?P<timestamp>.*)\]\s\"(?P<message>.*)\"$'
        storeExpresion = r'^(?P<timestamp>\d+\.\d+)\s+(?P<message>.*)$'


        #Identificamos el tipo de log
        if((re.search(accessExpresion, raw)) != None):
            attributes = re.match(accessExpresion, raw).groupdict()

            #Concatenamos el tiempo de procesamiento del proxy con el resto del mensaje del log
            attributes['message'] = attributes['time'] + " " + attributes['message'] 

            #Borramos el atributo temporal time
            del attributes['time']

            attributes['timestamp'] = datetime.datetime.utcfromtimestamp(float(attributes['timestamp']))

        elif((re.search(cacheExpresion, raw)) != None):
            attributes = re.match(cacheExpresion, raw).groupdict()
            
            attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%Y/%m/%d %H:%M:%S')
        
        elif((re.search(refererExpresion, raw)) != None):
            attributes = re.match(refererExpresion, raw).groupdict()
            
            attributes['timestamp'] = datetime.datetime.utcfromtimestamp(float(attributes['timestamp']))
        
        elif((re.search(useragentExpresion, raw)) != None):
            attributes = re.match(useragentExpresion, raw).groupdict()
            
            #Pasamos la fecha a UTC
            attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
            attributes['timestamp'] = attributes['timestamp'].astimezone(timezone.utc)

        elif((re.search(storeExpresion, raw)) != None):
            attributes = re.match(storeExpresion, raw).groupdict()
            
            attributes['timestamp'] = datetime.datetime.utcfromtimestamp(float(attributes['timestamp']))

        attributes['timestamp'] = attributes['timestamp'].astimezone(timezone.utc)
        #Definimos el atributo app_name
        attributes['app_name'] = "Squid"

        super().__init__(**attributes, raw=raw)

class CupsLogs(Logs):

    def __init__(self, raw:str):

        # Expresion regular para los logs cups
        attributes = re.match(f'^[a-z]+[\s\-]*\[(?P<timestamp>{DATE}/{MONTH}/{YEAR}:{TIME}\s\-{NUMBER})\](?P<message>{DESCRIPTION})', raw, flags=re.IGNORECASE).groupdict()

        # Conversion a UTC
        attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        attributes['timestamp'] = attributes['timestamp'].astimezone(timezone.utc).replace(tzinfo=datetime.timezone.utc)

        # Definicion del atributo app_name
        attributes['app_name'] = "CUPS"
        super().__init__(**attributes, raw=raw)


class PrivoxyLogs(Logs):
    def __init__(self, raw: str):
        attributes = re.match(f'^(?P<timestamp>{MONTH} {DATE} {TIME}) (?P<host_name>\S+) (?:(?P<app_name>\S+))?(?P<message>.*)$', raw).groupdict()
        # parse time
        attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%b %d %H:%M:%S').replace(year=datetime.datetime.now().year).replace(tzinfo=datetime.timezone.utc)
        super().__init__(**attributes, raw=raw)

class HttpdLogs(Logs):
    def __init__(self, raw: str):
        attributes = re.match(f'^(?P<host_name>\S+) \S+ \S+ \[(?P<timestamp>{DATE}/{MONTH}/{YEAR}:{TIME} \S+)\] "(?P<message>.*)$', raw).groupdict()
        # parse time
        utc_minus_5 = datetime.datetime.strptime(attributes['timestamp'], '%d/%b/%Y:%H:%M:%S %z').replace(year=datetime.datetime.now().year)
        attributes['timestamp'] =utc_minus_5.astimezone(datetime.timezone.utc)
        super().__init__(**attributes, raw=raw)

def read_logs(log_file: str) -> List[str]:
    with open(log_file, 'r', encoding='utf8') as f:
        return [line for line in f]


def parse_logs(logs: List[str], parser_class: Type) -> List[Logs]:
    parsed_logs = []
    for log in logs:
        try:
            parsed_logs.append(parser_class(log))
        except AttributeError as e:
            print('AttributeError', e)
            continue
    return parsed_logs


# rules for parsing logs
rules = {
    r'boot.log(\.\d+)?': UnixLogs,
    r'cron(\.\d+)?': UnixLogs,
    r'access.log(\.\d+)?': SquidLogs,
    r'cache.log(\.\d+)?': SquidLogs,
    r'referer_log.log(\.\d+)?': SquidLogs,
    r'store.log(\.\d+)?': SquidLogs,
    r'useragent_log.log(\.\d+)?': SquidLogs,
    r'logfile': PrivoxyLogs,
    r'error_log(\.\d+)?': CupsLogs,
    r'ssl_access_log(\.\d+)?': HttpdLogs,
}

import pandas as pd

global_df = pd.DataFrame(columns=['priority', 'protocol_ver', 'timestamp', 'host_name', 'app_name', 'process_id', 'message_id', 'struct_data', 'message'])

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
                logs = parse_logs(logs, rules.get(key))
                break
        else:
            continue

        #print(*logs, sep='\n')

        data = {
            'priority': [log.priority for log in logs],
            'protocol_ver': [log.protocol_ver for log in logs],
            'timestamp': [log.timestamp for log in logs],
            'host_name': [log.host_name for log in logs],
            'app_name': [log.app_name for log in logs],
            'process_id': [log.process_id for log in logs],
            'message_id': [log.message_id for log in logs],
            'struct_data': [log.struct_data for log in logs],
            'message': [log.message for log in logs]
        }

        df = pd.DataFrame(data)
        global_df = pd.concat([global_df, df], ignore_index=True)

# global_df['timestamp'] = pd.to_datetime(global_df['timestamp'], utc=True).dt.tz_localize(tz='UTC')
sorted_global_df = global_df.sort_values(by='timestamp')
print(sorted_global_df['timestamp'])
