import re


class policySocial:
    def checkpolicySocialTCP(payloadToBeChecked):
        patternT1 = re.compile("\x2F\x2F\x5C\x5C",flags=2)

        if re.search(patternT1, payloadToBeChecked):
            return ("Alert!!!\t","POLICY-SOCIAL multiple chat protocols link to local file attempt")