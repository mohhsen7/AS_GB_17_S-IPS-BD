import re


class blackList:
    def checkBlackListTCP(payloadToBeChecked):
        patternT1 = re.compile("User-Agent\x3A SAH Agent",flags=2)
        patternT2 = re.compile("User-Agent\x3A Async HTTP Agent",flags=2) 
        patternT3 = re.compile("malware",flags=2) 
        patternT4 = re.compile("User-Agent\x3A Tear Application",flags=2) 
        patternT5 = re.compile("User-Agent\x3A TCYWinHTTPDownload",flags=2) 
        patternT6 = re.compile("\/inst\.php\?fff=",flags=2) 
        patternT7 = re.compile("\/tongji\.js",flags=2) 
        patternT8 = re.compile("User-Agent\x3A ErrCode",flags=2) 
        patternT9 = re.compile("User-Agent\x3A RookIE\/1\.0\x0D\x0A",flags=2) 
        patternT10 = re.compile("User-Agent\x3A SelectRebates",flags=2) 
        patternT11 = re.compile("User-Agent\x3A\x20wget\x20\x33\x2E\x30\x0D\x0A",flags=2) 
        patternT12 = re.compile("User-Agent\x3A\x20Error\x20Fix",flags=2) 
        patternT13 = re.compile("User-Agent\x3A\x20STORMDDOS",flags=2) 
        #patternT14 = re.compile("\/config\.ini|3322\\x2E\\xorg",flags=2) 
        patternT15 = re.compile("User-Agent\x3A\x20MacProtector",flags=2) 
        #patternT16 = re.compile("Subject\\x3A\\x You have received a Hallmark E-Card\!|href=\\x22\\xhttp\\x3A\\x\/\/www\.hallmark\.com\/",flags=2) 
        #patternT17 = re.compile("\/setup\_b\.asp\?prj=|\&pid=|\&mac=",flags=2) 
        patternT18 = re.compile("\/kx4\.txt",flags=2) 
        patternT19 = re.compile("\x26AnSSip=",flags=2) 
        patternT20 = re.compile("\/VertexNet\/tasks\.php\?uid=\x7B",flags=2) 
        #patternT21 = re.compile("\/r\_autoidcnt\.asp\?mer\_seq=|\&mac=",flags=2) 
        patternT22 = re.compile("\.sys\.php\?getexe=",flags=2) 
        patternT23 = re.compile("\/VertexNet\/adduser\.php\?uid=\x7B",flags=2) 
        #patternT24 = re.compile("\/blog\/images\/3521\.jpg\?v|\&tq=",flags=2) 
        #patternT25 = re.compile("\/app\/\?prj=|\&pid=|\&mac=",flags=2) 
        #patternT26 = re.compile("\/pte\.aspx\?ver=|\&rnd=",flags=2) 
        patternT27 = re.compile("\/1cup\/script\.php",flags=2) 
        #patternT28 = re.compile("\/install\.asp\?mac=|\&mode",flags=2) 
        #patternT29 = re.compile("\/vic\.aspx\?ver=|\&rnd=",flags=2) 
        patternT30 = re.compile("\/games\/java\_trust\.php\?f=",flags=2) 
        # for 8 is alone patternT31 = re.compile("User-Agent\x3A\x20Opera\x2F\x8\x2E\x89",flags=2) 
        patternT32 = re.compile("\/160\.rar",flags=2) 
        #patternT33 = re.compile("\/optima\/index\.php|uid=|ver=",flags=2) 
        patternT34 = re.compile("User-Agent\x3A Baby Remote",flags=2) 
        patternT35 = re.compile("User-Agent\x3A feranet\/0\.4\x0D\x0A",flags=2) 
        patternT36 = re.compile("User-Agent\x3A darkness",flags=2) 
        patternT37 = re.compile("User-Agent\x3A IPHONE",flags=2) 
        patternT38 = re.compile("User-Agent\x3A InfoBot\x2F",flags=2) 
        patternT39 = re.compile("User-Agent\x3A Meterpreter",flags=2) 
        patternT40 = re.compile("User-Agent\x3A 0pera 10",flags=2) 
        patternT41 = re.compile("User-Agent\x3A Mozilla\/\/4\.0 \[compatible",flags=2) 
        patternT42 = re.compile("User\x2DAgent\x3A MBVDFRESCT",flags=2) 
        patternT43 = re.compile("User\x2DAgent\x3A API\x2DGuide test program",flags=2) 
        patternT44 = re.compile("User-Agent\x3A Win32\x2FAmti",flags=2) 
        patternT45 = re.compile("User-Agent\x3A Flag\x3A",flags=2) 
        #patternT46 = re.compile("220\\x20|0wns j0",flags=2) 
        patternT47 = re.compile("User-Agent\x3A Aldi Bot",flags=2) 
        patternT48 = re.compile("221 Goodbye happy r00ting",flags=2) 
        patternT49 = re.compile("User-Agent\x3A\x20Google Bot\x0D\x0A",flags=2) 
        patternT50 = re.compile("User-Agent\x3A asafaweb\.com",flags=2) 
        patternT51 = re.compile("User-Agent\x3A\x20psi\x20v",flags=2) 
        patternT52 = re.compile("User-Agent\x3A YZF\x0D\x0A",flags=2) 
        patternT53 = re.compile("User-Agent\x3A 1234567890",flags=2) 
        patternT54 = re.compile("User-Agent\x3A\x20core-project",flags=2) 
        patternT55 = re.compile("User-Agent\x3A tl_v",flags=2) 
        patternT56 = re.compile("User-Agent\x3A mus",flags=2) 
        patternT57 = re.compile("User-Agent\x3A gbot",flags=2) 
        patternT58 = re.compile("User-Agent\x3A BOT\/0\.1 \x28BOT for JCE\x29",flags=2) 
        patternT59 = re.compile("User-Agent\x3A RAbcLib",flags=2) 
        patternT60 = re.compile("User-Agent\x3A Mozilla\/4\.0 \x28compatible\x3B MSIE 6\.0\x3BWindows NT 5\.1\x3B \.NET CLR 1\.1\.2150\x29",flags=2) 
        patternT61 = re.compile("\/runforestrun\?sid=",flags=2) 
        patternT62 = re.compile("User-Agent\x3A PoisonIvy",flags=2) 
        patternT63 = re.compile("User-Agent\x3A you\x0D\x0A",flags=2) 
        patternT64 = re.compile("User-Agent\x3A Alerter COM\+",flags=2) 
        patternT65 = re.compile("User-Agent\x3A Testing\x0D\x0A",flags=2) 
        patternT66 = re.compile("User-Agent: Opera\/9\.61\x0D\x0A",flags=2) 
        patternT67 = re.compile("User-Agent: vaccinepc",flags=2) 
        patternT68 = re.compile("User-Agent: Lizard\/1\.0\x0D\x0A",flags=2) 
        patternT69 = re.compile("User-Agent: test_hInternet\x0D\x0A",flags=2) 
        patternT70 = re.compile("\x0D\x0AUser-Agent\x3A\x20Google page\x0D\x0A",flags=2)         
        patternT71 = re.compile("User-Agent: User-Agent: Opera\/",flags=2) 
        patternT72 = re.compile("malware-sinkhole\x0D\x0A",flags=2) 
        patternT73 = re.compile("User-Agent\x3A\x20NewBrandTest\x0D\x0A",flags=2) 
        patternT74 = re.compile("User-Agent: me0hoi\x0D\x0A",flags=2) 
        patternT75 = re.compile("User-Agent: 04\/XP\x0D\x0A",flags=2) 
        patternT76 = re.compile("\/cgi-bin\/ms\/check",flags=2) 
        patternT77 = re.compile("User-Agent: User-Agent: Mozilla\/4\.0",flags=2) 
        patternT78 = re.compile("\/cgi-bin\/ms\/flush",flags=2) 
        patternT79 = re.compile("\/cgi-bin\/nt\/th",flags=2) 
        patternT80 = re.compile("\/cgi-bin\/win\/cab",flags=2) 
        patternT81 = re.compile("\/cgi-bin\/win\/wcx",flags=2) 
        patternT82 = re.compile("\/cgi-bin\/nt\/sk",flags=2) 
        patternT83 = re.compile("\/cgi-bin\/dllhost\/ac",flags=2) 
        patternT84 = re.compile("User-Agent\x3A cibabam\x0D\x0A",flags=2) 
        patternT85 = re.compile("User-Agent\x3A NOKIAN95\x2FWEB",flags=2) 
        patternT86 = re.compile("Mozilla\x2F3\.0 \x28Compatible\x29\x3BBrutus\x2FAET",flags=2) 
        patternT87 = re.compile("Opera\/10\x20",flags=2) 
        patternT88 = re.compile("User-Agent\x3A Win\x0D\x0A",flags=2) 
        patternT89 = re.compile("User-Agent\x3A Alina",flags=2) 
        patternT90 = re.compile("User-Agent: J13A\x0D\x0A",flags=2) 
        patternT91 = re.compile("User-Agent\x3A msctls_progress32\x0D\x0A",flags=2) 
        patternT92 = re.compile("User-Agent\x3A yahoonews\x0D\x0A",flags=2) 
        patternT93 = re.compile("User-Agent\x3A IExplore\x0D\x0A",flags=2) 
        patternT94 = re.compile("User-Agent\x3A umbra\x0D\x0A",flags=2) 
        patternT95 = re.compile("User-Agent: dtl2012\x0D\x0A",flags=2) 
        patternT96 = re.compile("\/botnet\/tasks\.php\?uid=\x7B",flags=2) 
        patternT97 = re.compile("\/botnet\/adduser\.php\?uid=\x7B",flags=2) 
        patternT98 = re.compile("User-Agent\x3A\x20SUiCiDE\/1\.5\x0D\x0A",flags=2) 
        patternT99 = re.compile("User-Agent: getURLDown\x0D\x0A",flags=2) 
        patternT100 = re.compile("User-Agent\x3A Zollard\x0D\x0A",flags=2)         
        
        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - SAH Agent")
        if re.search(patternT2, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Async HTTP Agent")
        if re.search(patternT3, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - malware")
        if re.search(patternT4, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Tear Application")
        if re.search(patternT5, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent TCYWinHTTPDownload")    
        if re.search(patternT6, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /inst.php?fff=")    
        if re.search(patternT7, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /tongji.js")    
        if re.search(patternT8, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious User-Agent ErrCode - W32/Fujacks.htm")    
        if re.search(patternT9, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string RookIE/1.0")    
        if re.search(patternT10, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent request for known PUA user agent - SelectRebates")    
        if re.search(patternT11, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious User-Agent wget 3.0")    
        if re.search(patternT12, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string ErrorFix")    
        if re.search(patternT13, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string STORMDDOS - Backdoor.Win32.Inject.ctt")    
        #if re.search(patternT14, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious uri config.ini on 3322.org domain")    
        if re.search(patternT15, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious User-Agent string MacProtector")    
        #if re.search(patternT16, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST EMAIL known malicious email string - You have received a Hallmark E-Card")    
        #if re.search(patternT17, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - /setup_b.asp?prj=")    
        if re.search(patternT18, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /kx4.txt")    
        if re.search(patternT19, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - AnSSip=")    
        if re.search(patternT20, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /VertexNet/tasks.php?uid=")    
        #if re.search(patternT21, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - /r_autoidcnt.asp?mer_seq=")    
        if re.search(patternT22, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - .sys.php?getexe=")    
        if re.search(patternT23, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /VertexNet/adduser.php?uid=")    
        #if re.search(patternT24, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - /blog/images/3521.jpg?v")    
        #if re.search(patternT25, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - /app/?prj=")    
        #if re.search(patternT26, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - pte.aspx?ver=")
        if re.search(patternT27, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /1cup/script.php")
        #if re.search(patternT28, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - /install.asp?mac=")
        #if re.search(patternT29, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - vic.aspx?ver=")
        if re.search(patternT30, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /games/java_trust.php?f=")
        #if re.search(patternT31, payloadToBeChecked):
            #return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string Opera/8.89 - P2P-Worm.Win32.Palevo.ddm")
        if re.search(patternT32, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /160.rar - Win32/Morto.A") 
        #if re.search(patternT33, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST URI request for known malicious URI - optima/index.php")
        if re.search(patternT34, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious User-Agent string Baby Remote - Win32/Babmote.A")
        if re.search(patternT35, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string feranet/0.4 - Win32/Ferabsa.A")
        if re.search(patternT36, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string - darkness")
        if re.search(patternT37, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string - IPHONE")        
        if re.search(patternT38, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string - InfoBot")
        if re.search(patternT39, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string - meterpreter")       
        if re.search(patternT40, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string 0pera 10")  
        if re.search(patternT41, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string Mozilla//4.0")
        if re.search(patternT42, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string MBVDFRESCT")
        if re.search(patternT43, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string API Guide test program")
        if re.search(patternT44, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string Win32 Amti")        
        if re.search(patternT45, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string Flag")
        #if re.search(patternT46, payloadToBeChecked):
            #print("Alert!!!\t","BLACKLIST known malicious FTP login banner - 0wns j0")       
        if re.search(patternT47, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string Aldi Bot")
        if re.search(patternT48, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST known malicious FTP quit banner - Goodbye happy r00ting")
        if re.search(patternT49, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string Google Bot")
        if re.search(patternT50, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent ASafaWeb Scan")
        if re.search(patternT51, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string psi")        
        if re.search(patternT52, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent YZF")
        if re.search(patternT53, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string 1234567890")       
        if re.search(patternT54, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string core-project")  
        if re.search(patternT55, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known Adware user agent Gamevance tl_v")
        if re.search(patternT56, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known Adware user agent mus - TDSS related")
        if re.search(patternT57, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known Adware user agent gbot")
        if re.search(patternT58, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent BOT/0.1")        
        if re.search(patternT59, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent RAbcLib")
        if re.search(patternT60, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Flame malware")       
        if re.search(patternT61, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for runforestrun - JS.Runfore")  
        if re.search(patternT62, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - PoisonIvy RAT")
        if re.search(patternT63, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - you")       
        if re.search(patternT64, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Alerter COM")  
        if re.search(patternT65, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Testing")
        if re.search(patternT66, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Opera/9.61")
        if re.search(patternT67, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - vaccinepc")
        if re.search(patternT68, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Lizard/1.0")        
        if re.search(patternT69, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - test_hInternet")
        if re.search(patternT70, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent - Google page")                 
        if re.search(patternT71, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - User-Agent User-Agent")  
        if re.search(patternT72, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST Connection to malware sinkhole")
        if re.search(patternT73, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - NewBrandTest")       
        if re.search(patternT74, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - me0hoi")  
        if re.search(patternT75, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - 04/XP")
        if re.search(patternT76, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/ms/check")
        if re.search(patternT77, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - User-Agent User-Agent")
        if re.search(patternT78, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/ms/flush")        
        if re.search(patternT79, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/nt/th")
        if re.search(patternT80, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/win/cab")            
        if re.search(patternT81, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/win/wcx")  
        if re.search(patternT82, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/nt/sk")
        if re.search(patternT83, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for /cgi-bin/dllhost/ac")       
        if re.search(patternT84, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent cibabam")  
        if re.search(patternT85, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent NOKIAN95/WEB")
        if re.search(patternT86, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known Malicious user agent Brutus AET")
        if re.search(patternT87, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent Opera 10")
        if re.search(patternT88, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Win")        
        if re.search(patternT89, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - Alina")
        if re.search(patternT90, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string J13A")  
        if re.search(patternT91, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - msctls_progress32")  
        if re.search(patternT92, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - yahoonews")
        if re.search(patternT93, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string IExplore")       
        if re.search(patternT94, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string umbra")  
        if re.search(patternT95, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user agent - dt12012")
        if re.search(patternT96, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /botnet/tasks.php?uid=")
        if re.search(patternT97, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST URI request for known malicious URI - /botnet/adduser.php?uid=")
        if re.search(patternT98, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string SUiCiDE/1.5")        
        if re.search(patternT99, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string getURLdown")
        if re.search(patternT100, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST User-Agent known malicious user-agent string - Linux.Trojan.Zollard")
        
    def checkBlackListUDP(payloadToBeChecked): 
        patternU1 = re.compile("\x0Cdatajunction\x03org\x00",flags=2)         
        patternU2 = re.compile("\x0Cguest-access\x03net\x00",flags=2)         
        patternU3 = re.compile("\x09secuurity\x03net\x00",flags=2)         
        patternU4 = re.compile("\x06gowin7\x03com\x00",flags=2)         
        patternU5 = re.compile("\x0Ddotnetadvisor\x04info\x00",flags=2)         
        patternU6 = re.compile("\x13bestcomputeradvisor\x03com\x00",flags=2)         
        patternU7 = re.compile("\x0Dmysundayparty\x03com\x00",flags=2)         
        patternU8 = re.compile("\x0Dprettylikeher\x03com\x00",flags=2)         
        patternU9 = re.compile("\x03mac\x06update\x04zyns\x03com",flags=2)         
        patternU10 = re.compile("\x0Cflashupdates\x04info\x00",flags=2)
        patternU11 = re.compile("\x0Cnvidiastream\x04info\x00",flags=2)         
        patternU12 = re.compile("\x08autosync\x04info\x00",flags=2)         
        patternU13 = re.compile("\x09dnsupdate\x04info\x00",flags=2)         
        patternU14 = re.compile("\x0Apingserver\x04info\x00",flags=2)         
        patternU15 = re.compile("\x09quick-net\x04info\x00",flags=2)         
        patternU16 = re.compile("\x0Brendercodec\x04info\x00",flags=2)         
        patternU17 = re.compile("\x0Asyncstream\x04info\x00",flags=2)         
        patternU18 = re.compile("\x0Clocalgateway\x04info\x00",flags=2)         
        patternU19 = re.compile("\x09dnsportal\x04info\x00",flags=2)         
        patternU20 = re.compile("\x0Ctraffic-spot\x03com\x00",flags=2) 
        patternU21 = re.compile("\x0Csmart-access\x03net\x00",flags=2)         
        patternU22 = re.compile("\x0Dnvidiadrivers\x04info\x00",flags=2)         
        patternU23 = re.compile("\x0Asyncdomain\x04info\x00",flags=2)         
        patternU24 = re.compile("\x07dnsmask\x04info\x00",flags=2)         
        patternU25 = re.compile("\x09videosync\x04info\x00",flags=2)         
        patternU26 = re.compile("\x0Ctraffic-spot\x03biz\x00",flags=2)         
        patternU27 = re.compile("\x0Anvidiasoft\x04info\x00",flags=2)         
        patternU28 = re.compile("\x0Bdnslocation\x04info\x00",flags=2)         
        patternU29 = re.compile("\x06jebena\x0Aananikolic\x02su\x00",flags=2)         
        patternU30 = re.compile("\x0Breslove-dns\x03com\x00",flags=2)
        patternU31 = re.compile("\x07openssh\x04info\x00",flags=2)         
        patternU32 = re.compile("\x0Flinuxrepository\x03org\x00",flags=2)         
        patternU33 = re.compile("\x10localfreecatalog\x03com\x00",flags=2)         
        patternU34 = re.compile("\x0Ataqyhucoka\x04info\x00",flags=2)         
        patternU35 = re.compile("\x0Amoqawowyti\x04info\x00",flags=2)         
        patternU36 = re.compile("\x0Afihyqukapy\x04info\x00",flags=2)         
        patternU37 = re.compile("\x0Fqecytylohozariw\x04info\x00",flags=2)         
        patternU38 = re.compile("\x0Fpornofreeforyou\x03com\x00",flags=2)         
        patternU39 = re.compile("\x0Adrafsddhjk\x03com\x00",flags=2)         
        patternU40 = re.compile("\x0Fxohuhynevepeqyv\x04info\x00",flags=2)  
        patternU41 = re.compile("\x0Bpornowinner\x03com\x00",flags=2)         
        patternU42 = re.compile("\x0Avesufopodu\x04info\x00",flags=2)         
        patternU43 = re.compile("\x0Adixegocixa\x04info\x00",flags=2)         
        patternU44 = re.compile("\x10shopcataloggroup\x03com\x00",flags=2)         
        patternU45 = re.compile("\x12newsearchnecessary\x03com\x00",flags=2)         
        patternU46 = re.compile("\x0Dnewsearchshop\x03com\x00",flags=2)         
        patternU47 = re.compile("\x0Fbeststoresearch\x03com\x00",flags=2)         
        patternU48 = re.compile("\x0Azykuxykevu\x04info\x00",flags=2)         
        patternU49 = re.compile("\x0Fkyqehurevynyryk\x04info\x00",flags=2)         
        patternU50 = re.compile("\x0Afacesystem\x02in\x00",flags=2)        
        
        if re.search(patternU1, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain datajunction.org - Gauss")
        if re.search(patternU2, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain guest-access.net - Gauss")
        if re.search(patternU3, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain secuurity.net - Gauss")
        if re.search(patternU4, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain gowin7.com - Gauss")
        if re.search(patternU5, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain dotnetadvisor.info - Gauss")
        if re.search(patternU6, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain bestcomputeradvisor.com - Gauss")        
        if re.search(patternU7, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain mysundayparty.com - Sykipot")
        if re.search(patternU8, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain prettylikeher.com - Sykipot")
        if re.search(patternU9, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain mac.update.zyns.com - OSX.Maljava")
        if re.search(patternU10, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain flashupdates.info - Flame")
        if re.search(patternU11, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain nvidiastream.info - Flame")
        if re.search(patternU12, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain autosync.info - Flame")
        if re.search(patternU13, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain dnsupdate.info - Flame")
        if re.search(patternU14, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain pingserver.info - Flame")
        if re.search(patternU15, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain quick-net.info - Flame")
        if re.search(patternU16, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain rendercodec.info - Flame")        
        if re.search(patternU17, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain syncstream.info - Flame")
        if re.search(patternU18, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain localgateway.info - Flame")
        if re.search(patternU19, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain dnsportal.info - Flame")
        if re.search(patternU20, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain traffic-spot.com - Flame")
        if re.search(patternU21, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain smart-access.net - Flame")
        if re.search(patternU22, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain nvidiadrivers.info - Flame")
        if re.search(patternU23, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain syncdomain.info - Flame")
        if re.search(patternU24, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain dnsmask.info - Flame")
        if re.search(patternU25, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain videosync.info - Flame")
        if re.search(patternU26, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain traffic-spot.biz - Flame")        
        if re.search(patternU27, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain nvidiasoft.info - Flame")
        if re.search(patternU28, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain dnslocation.info - Flame")
        if re.search(patternU29, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain jebena.ananikolic.su - Malware.HPsus/Palevo-B")
        if re.search(patternU30, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain reslove-dns.com - Dorifel")
        if re.search(patternU31, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain openssh.info - UNIX.Trojan.SSHDoor")
        if re.search(patternU32, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain linuxrepository.org - UNIX.Trojan.SSHDoor")
        if re.search(patternU33, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain localfreecatalog.com")
        if re.search(patternU34, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain taqyhucoka.info")
        if re.search(patternU35, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain moqawowyti.info")
        if re.search(patternU36, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain fihyqukapy.info")        
        if re.search(patternU37, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain qecytylohozariw.info")
        if re.search(patternU38, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain pornofreeforyou.com")
        if re.search(patternU39, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain drafsddhjk.com")
        if re.search(patternU40, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain xohuhynevepeqyv.info")
        if re.search(patternU41, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain pornowinner.com")
        if re.search(patternU42, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain vesufopodu.info")
        if re.search(patternU43, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain dixegocixa.info")
        if re.search(patternU44, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain shopcataloggroup.com")
        if re.search(patternU45, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain newsearchnecessary.com")
        if re.search(patternU46, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain newsearchshop.com")        
        if re.search(patternU47, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain beststoresearch.com")
        if re.search(patternU48, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain zykuxykevu.info")
        if re.search(patternU49, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain kyqehurevynyryk.info")
        if re.search(patternU50, payloadToBeChecked):
            return ("Alert!!!\t","BLACKLIST DNS request for known malware domain facesystem.in")
        