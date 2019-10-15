from enum import Enum

class DnsCategory(Enum):
    a_record = 1
    dns_validation = 2
    first_party = 3
    third_party = 4
    dns_error = 5
    pending = 6
