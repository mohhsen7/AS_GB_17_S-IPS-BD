import re


class puaAdware:
    def checkPuaAdwareTCP(payloadToBeChecked):
        #patternT1 = re.compile("\/\?dn=|pid=",flags=2)
        #patternT2 = re.compile("\/sk-logabpstatus\.php|a=|b=",flags=2)   
        #patternT3 = re.compile("\/gdi\?alpha=|0D\\x0A\\xCache-Control: no-store\,no-cache\\x0D\\x0A\\xPragma: no-cache\\x0D\\x0A\\xConnection: Keep-Alive\\x0D\\x0A\\x0D\\x0A|Accept|User-Agent:",flags=2) 
        #patternT4 = re.compile("\/gcs\?alpha=|0D\\x0A\\xCache-Control: no-store\,no-cache\\x0D\\x0A\\xPragma: no-cache\\x0D\\x0A\\xConnection: Keep-Alive\\x0D\\x0A\\x0D\\x0A|Accept|User-Agent:",flags=2)
        #patternT5 = re.compile("test\?extip=|exip=|pid=|gid=",flags=2)   
        #patternT6 = re.compile("\/img\/icons\/2040254\.32\.png|static\.updatestar\.net",flags=2) 
        #patternT7 = re.compile("\/install\/valid\?v|&unique_id=|www\.wajam\.com\\x0D\\x0A|User-Agent\\x3A",flags=2)
        #patternT8 = re.compile("&affid=|\/api\/|\?ts=|&token=|&group=|&nid=|&lid=|&ver=",flags=2)   
        #patternT9 = re.compile("\/UpdateStar\/\?v=|updatestarcdn\.com\\x0D\\x0A",flags=2) 
        #patternT10 = re.compile("\/ofr\/|updatestarcdn\.com\\x0D\\x0A",flags=2)
        patternT11 = re.compile("\/Apponic\/",flags=2)   
        #patternT12 = re.compile("\/\?pcrc=|&v=",flags=2) 
        #patternT13 = re.compile("\/ofr\/|\.cis",flags=2)
        #patternT14 = re.compile("\/script\/display\.php|User-Agent: Mozilla\/4\.0 \(compatible\\x3B\\x Win32\\x3B\\x WinHttp\.WinHttpRequest\.5)",flags=2)   
        #patternT15 = re.compile("\/RebateInformerSetup\.exe|User-Agent\\x3A\\x Inno Setup Downloader",flags=2)   
        #patternT16 = re.compile("\/get\/\?q=|User-Agent\\x3A\\x win32\\x0D\\x0A",flags=2) 
        #patternT17 = re.compile(",\\x22\\xinstallerBehavior\\x22\\x:\{\\x22\\xhideOnInstall\\x22\\x:|\{\\x22\\xtime\\x22\\x:|\\x22\\xcountry\\x22|,\\x22\\xcountryId\\x22\\x:",flags=2)
        #patternT18 = re.compile("\/aj\/|\.php\?p=|Referer\\x3A",flags=2)   
        #patternT19 = re.compile("\/op\?sid=|&dt=|&gid=",flags=2) 
        #patternT20 = re.compile("POST|\/api|Mozilla\/3\.0 \(compatible\\x3B\\x Indy Library\)\\x0D\\x0A|Referer\\x3A",flags=2)
        #patternT21 = re.compile("POST|\/\?v=|&pcrc=|Referer\\x3A\\x20\\x|Accept-",flags=2)   
        #patternT22 = re.compile("\/info\.php\?|quant=|f=|h=|size=",flags=2) 
        #patternT23 = re.compile("\/optin\.php\?|f=|quant=",flags=2)
        #patternT24 = re.compile("\/installer\.php\?|CODE=|UID=|action=",flags=2)        
        
        #if re.search(patternT1, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Trojan.InstantAccess variant outbound connection")
        #if re.search(patternT2, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Trojan.InstantAccess variant outbound connection") 
        #if re.search(patternT3, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Lucky Leap Adware outbound connection")   
        #if re.search(patternT4, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Lucky Leap Adware outbound connection")
        #if re.search(patternT5, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE IP address disclosure to advertisement sites attempt") 
        #if re.search(patternT6, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Wajam outbound connection - post install")  
        #if re.search(patternT7, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Wajam outbound connection - post install")            
        #if re.search(patternT8, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE FakeAV runtime detection")
        #if re.search(patternT9, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE UpdateStar encapsulated installer outbound connection") 
        #if re.search(patternT10, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE UpdateStar CIS file retrieval attempt")   
        if re.search(patternT11, payloadToBeChecked):
            return ("Alert!!!\t","PUA-ADWARE Apponic encapsulated installer outbound connection")
        #if re.search(patternT12, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Apponic encapsulated installer outbound connection") 
        #if re.search(patternT13, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Apponic CIS file retrieval attempt")   
        #if re.search(patternT14, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Amonetize installer outbound connection attempt")    
        #if re.search(patternT15, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.Inbox/PCFixSpeed/RebateInformer variant outbound connection") 
        #if re.search(patternT16, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.CloseApp variant outbound connection")  
        #if re.search(patternT17, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE SoftPulse variant HTTP response attempt")            
        #if re.search(patternT18, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.Gamevance variant outbound connection")
        #if re.search(patternT19, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.OptimizerPro variant outbound connection") 
        #if re.search(patternT20, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.InstallMonster variant outbound connection")   
        #if re.search(patternT21, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.Dealply outbound POST attempt")
        #if re.search(patternT22, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.OpenSoftwareUpdater variant outbound connection attempt") 
        #if re.search(patternT23, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.OpenSoftwareUpdater variant outbound connection attempt")   
        #if re.search(patternT24, payloadToBeChecked):
            #print("Alert!!!\t","PUA-ADWARE Win.Adware.OpenSoftwareUpdater variant outbound connection attempt")
            