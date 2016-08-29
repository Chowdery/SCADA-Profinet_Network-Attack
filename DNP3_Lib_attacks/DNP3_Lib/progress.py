__author__ = 'Nicholas Rodofile'
import sys
import time

for i in range(100):
  sys.stdout.write('\r[{0}{1}] {2}'.format('#'*(i/10), ' '*(10-i/10), i))
  time.sleep(0.1)