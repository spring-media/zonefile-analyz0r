from enum import Enum

class DnsCategory(Enum):
    a_record = 1
    first_party = 2
    third_party = 3
    dns_validation = 4
    dns_error = 5
    pending = 6
