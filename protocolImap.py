import re


class protocolImap:
    def checkprotocolImapTCP(payloadToBeChecked):
        patternT1 = re.compile("AUTHENTICATE CRAM-MD5",flags=2)

        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","PROTOCOL-IMAP CRAM-MD5 authentication request detected")