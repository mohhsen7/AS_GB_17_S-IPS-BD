import re

class browserOther:
    def checkbrowserOtherTCP(payloadToBeChecked):
        #patternT1 = re.compile("nim:import\?|filename=|>",flags=2)
        patternT2 = re.compile("User-Agent\x3A tnftp\/",flags=2)
        
        #if re.search(patternT1, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-OTHER Novell Messenger Client nim URI handler buffer overflow attempt")
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","BROWSER-OTHER FreeBSD tnftp client detected")
