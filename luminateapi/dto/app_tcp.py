from .common import *


class TCPTunnelSetting:
    def __init__(self, target, ports):
        self.target = target
        self.ports = ports

    def to_dict(self):
        return {"target": from_str(self.target),
                "ports": from_list(from_int, self.ports)}
