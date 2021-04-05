import re


class protocolVoip:
    def checkprotocolVoipTCP(payloadToBeChecked):
        patternT1 = re.compile("\x00\x00\x00\x00\x11\x01\x00\x00\x01\x00\x00\x00",flags=2)
        patternT2 = re.compile("Asterisk Call Manager",flags=2)   
        
        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-VOIP Digium Asterisk SCCP call state message offhook")
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-VOIP Digium Asterisk Manager Interface initial banner") 