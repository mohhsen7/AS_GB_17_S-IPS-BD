import re


class protocolTelnet:
    def checkprotocolTelnetTCP(payloadToBeChecked):
        patternT1 = re.compile("\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6\xFF\xF6",flags=2)
        
        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-TELNET Microsoft Telnet Server buffer overflow attempt")
        