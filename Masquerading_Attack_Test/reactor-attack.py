#Daniel J. Cowdery
#IFN701 - Network Attack Dataset (Masquerading Attack)

from Directory import *

import snap7
import snap7.partner
from snap7.snap7types import*
from snap7.util import*


reactor_client = snap7.client.Client()
reactor_client.connect(reactor_IP,0,1)