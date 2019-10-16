from __future__ import annotations
from typing import Optional
from .DnsCategory import DnsCategory

class DnsCheck:

    domain: str
    typ: str
    status: str
    category: DnsCategory
    sub_check: Optional[DnsCheck]

    def __init__(self, domain: str, typ: str, status: status = "pending", category: DnsCategory = DnsCategory.pending, sub_check: Optional[DnsCheck] = None) -> DnsCheck:
        self.domain = domain
        self.typ = typ
        self.status = status
        self.category = DnsCategory
        self.sub_check = sub_check
        
    def __repr__(self) -> str:
        return "DnsCheck<[{}]{},status={},cat={},subs={}>)".format(self.typ, self.domain, self.status, self.category, self.sub_check)

    def dns_trace(self) -> str:
        if not self.sub_check:
            return '[{}]{}'.format(self.typ, self.domain)
        else:
            return '[{}]{}\n-> {}'.format(self.typ, self.domain, self.sub_check.dns_trace())

    def effective_category(self) -> DnsCategory:
        if not self.sub_check:
            return self.category
        else:
            return DnsCategory(max(self.category.value, self.sub_check.effective_category().value))
