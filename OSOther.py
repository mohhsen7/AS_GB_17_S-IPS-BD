import re

class OSOther:
    def checkOSOtherTCP(payloadToBeChecked):
        patternT1 = re.compile("User-Agent: xmlset_roodkcableoj28840ybtide\x0D\x0A",flags=2)
        patternT2 = re.compile("\(\) \{",flags=2)
        patternT3 = re.compile("%3D%28%29\+%7B",flags=2)
        #patternT4 = re.compile("\(\) \{|RCPT|TO\\x3A",flags=2)
        #patternT5 = re.compile("\(\) \{|MAIL|FROM\\x3A",flags=2)
        #patternT6 = re.compile("USER |\(\) \{",flags=2)
        #patternT7 = re.compile("for|in \{|7C\\x bash \\x7C\\x7C",flags=2)
        patternT8 = re.compile("printf '<<EOF %\.0s' \{1\.\.",flags=2)
        patternT9 = re.compile("<<EOF <<EOF <<EOF <<EOF <<EOF <<EOF",flags=2)
        #patternT10 = re.compile("PASS|\(\) \{",flags=2)
        patternT11 = re.compile("DYLD_PRINT_TO_FILE=",flags=2)
              
        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER DLink DIR-100 User-Agent backdoor access attempt")
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER Bash CGI environment variable injection attempt")
        if re.search(patternT3, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER Bash CGI environment variable injection attempt")
        #if re.search(patternT4, payloadToBeChecked):
            #print("Alert!!!\t","OS-OTHER Bash environment variable injection attempt")
        #if re.search(patternT5, payloadToBeChecked):
            #print("Alert!!!\t","OS-OTHER Bash environment variable injection attempt")    
        #if re.search(patternT6, payloadToBeChecked):
            #print("Alert!!!\t","OS-OTHER Bash environment variable injection attempt")    
        #if re.search(patternT7, payloadToBeChecked):
            #print("Alert!!!\t","OS-OTHER Bash CGI nested loops word_lineno denial of service attempt")    
        if re.search(patternT8, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER Bash redir_stack here document handling denial of service attempt")    
        if re.search(patternT9, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER Bash redir_stack here document handling denial of service attempt")    
        #if re.search(patternT10, payloadToBeChecked):
            #print("Alert!!!\t","OS-OTHER Bash environment variable injection attempt")    
        if re.search(patternT11, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER OS X DYLD_PRINT_TO_FILE privilege escalation attempt") 
        
    def checkOSOtherUDP(payloadToBeChecked):
        patternU1 = re.compile("\x02\x01\x06\x00",flags=2)
        
        if re.search(patternU1, payloadToBeChecked):
            return ("Alert!!!\t","OS-OTHER Malicious DHCP server bash environment variable injection attempt")
