#make the firewalll on
import subprocess
subprocess.check_call('netsh.exe advfirewall set publicprofile state on')
subprocess.check_call('netsh.exe advfirewall set privateprofile state on')
subprocess.check_call('netsh.exe advfirewall set domainprofile state on')
