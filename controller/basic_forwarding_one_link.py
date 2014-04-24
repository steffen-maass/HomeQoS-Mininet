from pyretic.lib.corelib import *
from pyretic.lib.query import *


class basic_forwarding(DynamicPolicy):
    def __init__(self):
        super(basic_forwarding, self).__init__()

        self.basic = if_(match(switch=8796758988785, inport=1), fwd(5),
                         if_(match(switch=8796758988785, inport=5), fwd(1),
                             if_(match(switch=8796759375755, inport=1), fwd(5),
                                 if_(match(switch=8796759375755, inport=5), fwd(1), drop))))

        self.policy = self.basic


def main():
    return basic_forwarding()