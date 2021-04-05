import re


class browserFirefox:
    def checkbrowserFirefoxTCP(payloadToBeChecked):
        #patternT1 = re.compile("readystatechange|addEventListener|ArrayBuffer\(|Int32Array|window\.stop|ArrayBufferView",flags=2)
        #patternT2 = re.compile("document\.onreadystatechange|window\.parent\.frames\[0\]\.frameElement\.ownerDocument\.write\(",flags=2)   
        #patternT3 = re.compile("document\.onreadystatechange|window\.parent\.frames\[0\]\.frameElement\.ownerDocument\.write\(",flags=2)
        #patternT4 = re.compile("mozRTCPeerConnection\\x28\\x29|createOffer\\x28|window\.open\\x28\\x28\\xfunction|window\.open\\x28\\x27\\xchrome\\x3A\\x\/\/browser\/content\/browser\.xul",flags=2)   
        #patternT5 = re.compile("\<script|animVal|initialize|animVal|\<svg",flags=2)
        #patternT6 = re.compile("\<script|animVal|replaceItem|animVal|\<svg",flags=2) 
        #patternT7 = re.compile("\<script|animVal|insertItemBefore|animVal|\<svg",flags=2)
        #patternT8 = re.compile("window|mozRTC|PeerConnection|createOffer",flags=2)            
        
        #if re.search(patternT1, payloadToBeChecked) or re.search(patternT2, payloadToBeChecked) or re.search(patternT3, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-FIREFOX Mozilla Firefox 17 onreadystatechange memory corruption attempt")
        #if re.search(patternT4, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-FIREFOX Mozilla Firefox IDL fragment privilege escalation attempt") 
        #if re.search(patternT5, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-FIREFOX Mozilla Firefox DOMSVGLength initialize use after free attempt")             
        #if re.search(patternT6, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-FIREFOX Mozilla Firefox DOMSVGLength replaceItem use after free attempt") 
        #if re.search(patternT7, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-FIREFOX Mozilla Firefox DOMSVGLength insertItemBefore use after free attempt")                         
        #if re.search(patternT8, payloadToBeChecked):
            #print("Alert!!!\t","BROWSER-FIREFOX Mozilla Firefox IDL fragment privilege escalation attempt")             
        return