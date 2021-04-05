import re

class OSMobile:
    def checkOSMobileTCP(payloadToBeChecked):
        patternT1 = re.compile("\/farm\.php\?imei=",flags=2)
        patternT2 = re.compile("C7\x04\x24\xD4\x74\x0E\x33\xE8\x16\xFB\xFF\xFF\x89\x45\xD4\x8B\x45\xD4\x01\x45\xDC\x8B\x45\xDC\x89\x44\x24\x04\xC7\x04\x24\x43\x43\x43\x43",flags=2)
              
        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","OS-MOBILE Android Andr.Trojan.Waller information disclosure attempt")
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","OS-MOBILE iOS lockdownd plist object buffer overflow attempt")
