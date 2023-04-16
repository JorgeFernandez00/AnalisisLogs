import dataclasses
import datetime 
import os.path
import re
from typing import Union, List, Dict, Type
from datetime import timezone

LOG_DIR = '/root/deiso/Repositorio/AnalisisLogs/hnet-hon-var-log-02282006/var/log/squid/descomprimidos'
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

        self.timestamp = self.timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f+%z')

        return f'<{self.priority}>{self.protocol_ver} {self.timestamp} {self.host_name} {self.app_name} {self.process_id} {self.message_id} {struct_data} {self.message}'


class UnixLogs(Logs):
    def __init__(self, raw: str):
        attributes = re.match(f'^(?P<timestamp>{MONTH} {DATE} {TIME}) (?P<host_name>\S+) (?:(?P<app_name>\S+)(?:\[(?P<process_id>\d+)\]): )?(?P<message>.*)$', raw).groupdict()
        
        print("fecha1", attributes['timestamp'])
        
        attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%b %d %H:%M:%S').replace(year=datetime.datetime.now().year)

        print("fecha2", attributes['timestamp'])
        super().__init__(**attributes, raw=raw)

class SquidLogs(Logs):  
    def __init__(self, raw: str):

        accessExpresion = r'^(?P<timestamp>\d+\.\d+)\s+(?P<time>\d+)\s+(?P<host_name>\S+)\s+(?P<message>.*)$'   # https://www.websense.com/content/support/library/web/v773/wcg_help/squid.aspx
        cacheExpresion = r'^(?P<timestamp>^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\|\s(?P<message>.*)$'
        refererExpresion = r'^(?P<timestamp>\d+\.\d+)\s(?P<host_name>\S+)\s(?P<message>(http|https).*)$' #https://etutorials.org/Server+Administration/Squid.+The+definitive+guide/Chapter+13.+Log+Files/13.4+referer.log/
        useragentExpresion = r'^(?P<host_name>\S+)\s+\[(?P<timestamp>.*)\]\s\"(?P<message>.*)\"$'
        storeExpresion = r'^(?P<timestamp>\d+\.\d+)\s+(?P<message>.*)$'


        #Identificamos el tipo de log
        if((re.search(accessExpresion, raw)) != None):
            attributes = re.match(accessExpresion, raw).groupdict()

            #Concatenamos el tiempo de procesamiento del proxy con el resto del mensaje del log
            attributes['message'] = attributes['time'] + " " + attributes['message'] 

            #Borramos el atributo temporal time
            del attributes['time']

            # parse time
            attributes['timestamp'] = datetime.datetime.utcfromtimestamp(float(attributes['timestamp']))

        elif((re.search(cacheExpresion, raw)) != None):
            attributes = re.match(cacheExpresion, raw).groupdict()
            
            attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%Y/%m/%d %H:%M:%S')
        
        elif((re.search(refererExpresion, raw)) != None):
            attributes = re.match(refererExpresion, raw).groupdict()
            
            # parse time
            attributes['timestamp'] = datetime.datetime.utcfromtimestamp(float(attributes['timestamp']))        
        
        elif((re.search(useragentExpresion, raw)) != None):
            attributes = re.match(useragentExpresion, raw).groupdict()
            
            attributes['timestamp'] = datetime.datetime.strptime(attributes['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
            attributes['timestamp'] = attributes['timestamp'].astimezone(timezone.utc)
            attributes['timestamp'] = attributes['timestamp'].replace(tzinfo=None)

        elif((re.search(storeExpresion, raw)) != None):
            attributes = re.match(storeExpresion, raw).groupdict()
            
            attributes['timestamp'] = datetime.datetime.utcfromtimestamp(float(attributes['timestamp']))
        
        #Definimos el atributo app_name
        attributes['app_name'] = "Squid"

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
    r'access.log(\.\d+)?': SquidLogs,
    r'cache.log(\.\d+)?': SquidLogs,
    r'referer_log.log(\.\d+)?': SquidLogs,
    r'store.log(\.\d+)?': SquidLogs,
    r'useragent_log.log(\.\d+)?': SquidLogs,
}


"""for root, dirs, files in os.walk(LOG_DIR):
    for file in files:
        # skip files with weird encoding or compressed files
        
        try:
            logs = read_logs(os.path.join(root, file))
        except UnicodeDecodeError:
            print('UnicodeDecodeError', os.path.join(root, file))
            continue

        logs = parse_logs(logs, SquidLogs)

        print(*logs, sep='\n')"""

root = "/root/deiso/Repositorio/AnalisisLogs/hnet-hon-var-log-02282006/var/log/squid/descomprimidos"
file = "cache.log"

try:
    logs = read_logs(os.path.join(root, file))
except UnicodeDecodeError:
    print('UnicodeDecodeError', os.path.join(root, file))

logs = parse_logs(logs, SquidLogs)

print(*logs, sep='\n')

