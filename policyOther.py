import re


class policyOther:
    def checkpolicyOtherTCP(payloadToBeChecked):
        patternT1 = re.compile("\/CFIDE\/adminapi",flags=2)
        patternT2 = re.compile("\/CFIDE\/componentutils",flags=2)
        patternT3 = re.compile("\/CFIDE\/administrator",flags=2)
        patternT4 = re.compile("USER\x20images\x0D\x0A",flags=2)
        patternT5 = re.compile("PASS\x20images\x0D\x0A",flags=2)
        patternT6 = re.compile("the one-time use of the username \x22cisco\x22 with the \x0Apassword \x22cisco\x22\.",flags=2)
            
        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-OTHER Adobe ColdFusion admin API access attempt")    
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-OTHER Adobe ColdFusion component browser access attempt")       
        if re.search(patternT3, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-OTHER Adobe ColdFusion admin interface access attempt")    
        if re.search(patternT4, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-OTHER QLogic Switch 5600/5800 default ftp login attempt")       
        if re.search(patternT5, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-OTHER QLogic Switch 5600/5800 default ftp login attempt")  
        if re.search(patternT6, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-OTHER Cisco router Security Device Manager default banner")