import re


class protocolPop:
    def checkprotocolPopTCP(payloadToBeChecked):
        patternT1 = re.compile("STAT",flags=2)

        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-POP STAT command")