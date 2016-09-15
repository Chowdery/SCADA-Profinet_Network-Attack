#Daniel J. Cowdery
#IFN701 - Network Attack Dataset (Masquerading Attack)

from Conveyor_Belt import*
from Directory import *


try:
    victim = ConveyorBelt()

    while (victim.run):

        victim.CheckStatus()

        if victim.option == 0:
            victim.ToggleMotor()

        elif victim.option == 1:
            victim.SetFlopgateRight()

        elif victim.option == 2:
            victim.SetFlopgateLeft()

        elif victim.option == 7:
            victim.ToggleConveyorDirection()

        elif victim.option == 8:
            victim.ToggleFlopgateDirection()

        elif victim.option == 99:
            victim.PrintStatus()

        elif victim.option == 55:
            victim.TEST_PrintDWORDStatus()

        elif victim.option == 56:
            victim.TEST_PrintINTStatus()

        elif victim.option == 57:
            victim.TEST_PrintREALStatus()

        elif victim.option == 58:
            victim.TEST_PrintStringStatus()

        victim.PrintOptions()

except KeyboardInterrupt:
    print "\nTerminating application..."
    victim.Exit()

except Snap7Exception:
    print "\nCould not connect to victim. Terminating application!"