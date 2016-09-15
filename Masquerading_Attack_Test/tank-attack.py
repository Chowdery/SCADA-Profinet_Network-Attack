#Daniel J. Cowdery
#IFN701 - Network Attack Dataset (Masquerading Attack)

from Directory import *

import snap7
import snap7.partner
from snap7.snap7types import*
from snap7.util import*


tank_client = snap7.client.Client()
tank_client.connect(tank_IP,0,1)



