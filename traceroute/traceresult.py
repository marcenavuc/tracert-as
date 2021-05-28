import re
from dataclasses import dataclass
from typing import Dict

RESULT_RE = re.compile(r"\((.+)\)")


@dataclass(repr=True, unsafe_hash=True, frozen=True, eq=True)
class TraceResult:
    is_local: bool
    route: str = ""
    net_name: str = ""
    as_zone: str = ""
    country: str = ""

    @classmethod
    def get_from_data(cls, data: Dict):
        is_local = data is None
        if not is_local:
            route = data.get('route', '')
            net_name = data.get('netname', '')
            as_zone = data.get('origin', '')
            country = data.get('country', '')
            return cls(is_local, route, net_name, as_zone, country)
        return cls(is_local)

    def __str__(self):
        # return re.findall(RESULT_RE, self.__repr__())[0]
        return f"{self.route}\r\n{self.net_name} {self.as_zone} {self.country}"
