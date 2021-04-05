import re


class puaOther:
    def checkPuaOtherTCP(payloadToBeChecked):
        patternT1 = re.compile("Host\x3A pierrejb\.agora\.eu\.org",flags=2)

        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","PUA-OTHER Request for known malware domain pierrejb.agora.eu.org")
