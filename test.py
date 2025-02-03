import psutil
from pprint import pprint

adapters = psutil.net_if_addrs()
pprint(adapters)
