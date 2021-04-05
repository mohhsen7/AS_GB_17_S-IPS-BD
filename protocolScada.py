import re


class protocolScada:
    def checkprotocolScadaTCP(payloadToBeChecked):
        patternT1 = re.compile("\x64\xA1\x18\x00\x00\x00\x83\xC0\x08\x8B\x20\x81\xC4\x30\xF8\xFF\xFF",flags=2)
        patternT2 = re.compile("\xD2\x04\x00\x00\x7B\x00\x00\x00",flags=2)
        patternT3 = re.compile("\x10\x60\x00\x00\x66\x66\x07\x00\x10\x00\x00\x00\x19\x00\x00\x00",flags=2)
        patternT4 = re.compile("\x00\x00\x00\x00",flags=2)

        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-SCADA Yokogawa CENTUM CS 3000 stack buffer overflow attempt")
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-SCADA KingSCADA Alarm Server stack buffer overflow attempt") 
        if re.search(patternT3, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-SCADA Schneider Electric IGSS integer underflow attempt")
        if re.search(patternT4, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-SCADA Schneider Electric IGSS integer underflow attempt") 
        