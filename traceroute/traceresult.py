from dataclasses import dataclass
from typing import Dict


@dataclass
class TraceResult:
    route: str
    net_name: str
    as_zone: str
    country: str
    is_local: bool

    @classmethod
    def get_from_data(cls, addr: str, data: Dict):
        is_local = data is None
        route = data.get('route', '') if not is_local else addr
        net_name = data.get('netname', '') if not is_local else ''
        as_zone = data.get('origin', '') if not is_local else ''
        country = data.get('country', '') if not is_local else ''
        return cls(route, net_name, as_zone, country, is_local)

    def __str__(self) -> str:
        result = f'{self.route}\n'
        if self.is_local:
            return f'{result}local'
        info = []
        if self.net_name:
            info.append(self.net_name)
        if self.as_zone:
            info.append(self.as_zone[2:])
        if self.country and self.country != 'EU':
            info.append(self.country)
        return result + ', '.join(info) if len(info) > 0 \
            else '*\t'
