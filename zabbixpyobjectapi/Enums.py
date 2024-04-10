from enum import Enum


class InterfaceType(Enum):
    AGENT = 1
    SNMP = 2
    IPMI = 3
    JMX = 4