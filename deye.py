#!/bin/env python3

from transport_tcp import *
from bitstring import ConstBitStream, BitStream, Bits

import sys
import socket
import libscrc
import json
import os
import datetime

# END CONFIG

class InformationObj(object):
    name = ""
    description = ""

    parsemap = {}
    unit = ""
    value = None
    val_min = 0
    val_max = 0
    val_default = 0

    def __init__(self, data=None, value=None):
        self.unparsed = bytes()
        if data is not None:
            start = data.pos
            for k,v in self.parsemap.items():
                if isinstance(v, str):
                    self.value = data.read(v)
                else:
                    self.value = v(data)
            self.rawdata = data[start:data.pos]
        else:
            if value >= self.val_min and value <= self.val_max:
                self.value = value
                self.update()

    def update(self):
        bits = BitStream()
        for k,v in self.parsemap.items():
            if isinstance(v, str):
                if "int" in v:
                    bits.append(Bits(f"{v}={int(self.value)}"))
                else:
                    bits.append(Bits(f"{v}={self.value}"))
            else:
                bits.append(Bits(bytes=self.value.toBytes()))
        self.rawdata = bits

    def update_recursive(self):
        for k,v in self.parsemap.items():
            if not isinstance(v, str):
                self.value.update_recursive()
        self.update()
        
    def toBits(self):
        return self.rawdata

    def __str__(self):
        return f"{self.name}: {self.value}{self.unit}"
    
    def __json__(self):
        return self.value


class InformationGroup(object):
    name = ""
    description = ""

    parsemap = []
    values = {}

    def __init__(self, rawbytes=None):
        data = ConstBitStream(rawbytes)
        self.unparsed = bytes()
        if data is not None:
            start = data.bytepos
            i = 0
            for p in self.parsemap:
                if isinstance(p, str):
                    pad = data.read(p)
                    self.values[f"UNPARSED_{i}"] = pad
                else:
                    self.values[p.name] = p(data)
                i+=1
            rest = data.read("hex")
            if rest:
                self.values[f"UNPARSED_REST"] = rest
            self.rawdata = data.bytes[start:data.bytepos]

    def update(self):
        bits = BitStream()
        i = 0
        for p in self.parsemap:
            if isinstance(p, str):
                ident = f"UNPARSED_{i}"
                bits.append(Bits(f"{p}={self.values[ident]}"))
            else:
                bits.append(Bits(self.values[p.name].toBits()))
            i+=1
        if "UNPARSED_REST" in self.values:
            rest = self.values["UNPARSED_REST"]
            bits.append(Bits(f"bin={rest}"))
        self.rawdata = bits.bytes
        
    def update_recursive(self):
        for p in self.parsemap:
            if not isinstance(p, str):
                self.values[p.name].update_recursive()
        self.update()
        
    def toBytes(self):
        return self.rawdata
        
    def __str__(self):
        out = ""
        for k,v in self.values.items():
            if isinstance(v, str):
                out += f" UNPARSED: {' '.join(v[i:i+8] for i in range(0, len(v), 8))}\n"
            else:
                out += f" {v}\n"
        return f"Name: {self.name}\n{self.description}\n{out}"
    
    def __json__(self):
        return self.values
        
class NestedInformationGroup(InformationGroup):
    def __init__(self, data=None):
        self.unparsed = bytes()
        if data is not None:
            start = data.bytepos
            i = 0
            for p in self.parsemap:
                if isinstance(p, str):
                    pad = data.read(p)
                    self.values[f"UNPARSED_{i}"] = pad
                else:
                    self.values[p.name] = p(data)
                i+=1
            self.rawdata = data.bytes[start:data.bytepos]
    
class FixedPNDecL(InformationObj):
    value = 0
    divider = 1
    length = 16

    def __init__(self, data=None, value=None):
        if data is not None:
            start = data.bytepos
            self.value = data.read(F"intbe:{self.length}") / self.divider
            self.rawdata = data.bytes[start:data.bytepos]
        else:
            self.value = value
            self.update()
            
    def update(self):
        bits = BitStream()
        bits.append(Bits(f"intbe:{self.length}={int(float(self.value)*self.divider):d}"))
        self.rawdata = bits.bytes
        
    def update_recursive(self):
        self.update()
        
    def toBytes(self):
        return self.rawdata
        
    def __str__(self):
        return f"{self.value}"
    
    def __float__(self):
        return self.value
    
    def __json__(self):
        return float(self)    
    
class FixedPOneDec16(FixedPNDecL):
    value = 0
    divider = 10
    length = 16  
    
class FixedPTwoDec16(FixedPNDecL):
    value = 0
    divider = 100
    length = 16
    

class FixedPOneDec32(InformationObj):
    value = 0

    def __init__(self, data=None, value=None):
        if data is not None:
            start = data.bytepos
            low = data.read("intbe:16")
            high = data.read("intbe:16")
            self.value = ((high << 16) + low) / 10
            self.rawdata = data.bytes[start:data.bytepos]
        else:
            self.value = value
            self.update()
            
    def update(self):
        bits = BitStream()
        val = int(float(self.value) * 10)
        high = val >> 16
        low = val & 0x0000ffff
        bits.append(Bits(f"intbe:16={low:d}"))
        bits.append(Bits(f"intbe:16={high:d}"))
        self.rawdata = bits.bytes
        

class rDeyeStart(InformationObj):
    name = "DeyeStart"
    description = ""
    parsemap = {"val":"hex:8"}
    
class rLength(InformationObj):
    name = "Length"
    description = ""
    parsemap = {"val":"uintle:16"}
    
class rControlCode(InformationObj):
    name = "ControlCode"
    description = ""
    parsemap = {"val":"hex:16"}
    
class rFrameNum(InformationObj):
    name = "FrameNum"
    description = ""
    parsemap = {"val":"uintbe:16"}
    
class rInvSerial(InformationObj):
    name = "InvSerial"
    description = ""
    parsemap = {"val":"uintle:32"}

class rDeyeCRC(InformationObj):
    name = "DeyeCRC"
    description = ""
    parsemap = {"val":"hex:8"}
    
class rDeyeEnd(InformationObj):
    name = "DeyeEnd"
    description = ""
    parsemap = {"val":"hex:8"}

class rModbusCommand(InformationObj):
    name = "ModbusCommand"
    description = ""
    parsemap = {"val":"hex:16"}
    
class rModbusLength(InformationObj):
    name = "ModbusLength"
    description = ""
    parsemap = {"val":"uint:8"}
    
class rModbusCRC(InformationObj):
    name = "ModbusCRC"
    description = ""
    parsemap = {"val":"hex:16"}
    
class sDeviceType(InformationObj):
    name = "sDeviceType"
    description = ""
    parsemap = {"val":"hex:16"}
    
class sModbusAddress(InformationObj):
    name = "sModbusAddress"
    description = ""
    parsemap = {"val":"uintle:16"}
    
class sComProtoVersion(InformationObj):
    name = "sComProtoVersion"
    description = ""
    parsemap = {"val":"bytes:2"}
    
class sSerial(InformationObj):
    name = "sSerial"
    description = ""
    parsemap = {"val":"bytes:10"}

class sRatedPower(InformationObj):
    name = "sRatedPower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "W"
    
class sNumMPPT(InformationObj):
    name = "sNumMPPT"
    description = ""
    parsemap = {"val":"uint:8"}
    
class sNumPhases(InformationObj):
    name = "sNumPhases"
    description = ""
    parsemap = {"val":"uint:8"}

class pRatedGridVoltage(InformationObj):
    name = "pRatedGridVoltage"
    description = ""
    parsemap = {"val":"hex:16"}
    
class pRemoteLockEnabled(InformationObj):
    name = "pRemoteLockEnabled"
    description = ""
    parsemap = {"val":"uint:16"}
    
class pPostTime(InformationObj):
    name = "pPostTime"
    description = ""
    parsemap = {"val":"uint:16"}
    unit = "s"
    
class pSystemTime(InformationObj):
    name = "pSystemTime"
    description = ""
    parsemap = {"val":"hex:48"}

class pGridVoltageUpperLimit(InformationObj):
    name = "pGridVoltageUpperLimit"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class pGridVoltageLowerLimit(InformationObj):
    name = "pGridVoltageLowerLimit"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class pGridFrequencyUpperLimit(InformationObj):
    name = "pGridFrequencyUpperLimit"
    description = ""
    parsemap = {"val":FixedPTwoDec16}
    unit = "Hz"
    
class pGridFrequencyLowerLimit(InformationObj):
    name = "pGridFrequencyLowerLimit"
    description = ""
    parsemap = {"val":FixedPTwoDec16}
    unit = "Hz"
    
class pGridCurrentUpperLimit(InformationObj):
    name = "pGridCurrentUpperLimit"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "A"

class pActivePowerRegulation(InformationObj):
    name = "pActivePowerRegulation"
    description = ""
    parsemap = {"val":"uint:16"}
    unit = "%"
    
class pSwitchEnable(InformationObj):
    name = "pSwitchEnable"
    description = ""
    parsemap = {"val":"uint:16"}
    
class pFactoryResetEnable(InformationObj):
    name = "pFactoryResetEnable"
    description = ""
    parsemap = {"val":"uint:16"}
    
class pSelfCheckingTimeIsland(InformationObj):
    name = "pSelfCheckingTimeIsland"
    description = ""
    parsemap = {"val":"uint:16"}
    unit = "s"
    
class pIslandProtectionEnable(InformationObj):
    name = "pIslandProtectionEnable"
    description = ""
    parsemap = {"val":"uint:16"}

class sRunState(InformationObj):
    name = "sRunState"
    description = ""
    parsemap = {"val":"uint:16"}
    
class sDayActivePower(InformationObj):
    name = "sDayActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "kWh"
    
class sUptime(InformationObj):
    name = "sUptime"
    description = ""
    parsemap = {"val":"uint:16"}
    unit = "min"
    
class sTotalActivePower(InformationObj):
    name = "sTotalActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "kWh"
    
class sModule1DayActivePower(InformationObj):
    name = "sModule1DayActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "kWh"
    
class sModule2DayActivePower(InformationObj):
    name = "sModule2DayActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "kWh"
    
class sModule3DayActivePower(InformationObj):
    name = "sModule3DayActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "kWh"
    
class sModule4DayActivePower(InformationObj):
    name = "sModule4DayActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "kWh"
    
class sModule1TotalActivePower(InformationObj):
    name = "sModule1TotalActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "kWh"
    
class sModule2TotalActivePower(InformationObj):
    name = "sModule2TotalActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "kWh"
    
class sModule3TotalActivePower(InformationObj):
    name = "sModule3TotalActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "kWh"
    
class sModule4TotalActivePower(InformationObj):
    name = "sModule4TotalActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "kWh"
    
class sGridVoltage(InformationObj):
    name = "sGridVoltage"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class sGridCurrent(InformationObj):
    name = "sGridCurrent"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "A"
    
class sGridFrequency(InformationObj):
    name = "sGridFrequency"
    description = ""
    parsemap = {"val":FixedPTwoDec16}
    unit = "Hz"
    
class sActivePower(InformationObj):
    name = "sActivePower"
    description = ""
    parsemap = {"val":FixedPOneDec32}
    unit = "W"
    
class sTemperature(InformationObj):
    name = "sTemperature"
    description = ""
    parsemap = {"val":FixedPTwoDec16}
    unit = "°C"
    
class sModule1Voltage(InformationObj):
    name = "sModule1Voltage"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class sModule2Voltage(InformationObj):
    name = "sModule2Voltage"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class sModule3Voltage(InformationObj):
    name = "sModule3Voltage"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class sModule4Voltage(InformationObj):
    name = "sModule4Voltage"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "V"
    
class sModule1Current(InformationObj):
    name = "sModule1Current"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "A"
    
class sModule2Current(InformationObj):
    name = "sModule2Current"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "A"
    
class sModule3Current(InformationObj):
    name = "sModule3Current"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "A"
    
class sModule4Current(InformationObj):
    name = "sModule4Current"
    description = ""
    parsemap = {"val":FixedPOneDec16}
    unit = "A"

class ModbusRequest:
    DEYE_READ="0103"
    DEYE_WRITE="0110"

    def __init__(self, mode=DEYE_READ, start_reg=60, count_reg=10):
        self.mode = mode
        self.start_reg = start_reg
        self.count_reg = count_reg
        
        self.update()
        
    def genCRC(self):
        modbus_crc=bytearray.fromhex("{:04x}".format(libscrc.modbus(self.rawbytes[0:6])))
        modbus_crc.reverse()
        return modbus_crc

    def update(self):
        self.rawbytes = bytearray.fromhex(F"{self.mode}{self.start_reg:04x}{self.count_reg:04x}")
        self.rawbytes += self.genCRC()
        
        return self
        
    def toBytes(self):
        return self.rawbytes


class DeyeTCPRequest:
    START = bytearray.fromhex("A5")
    CONTROLCODE = bytearray.fromhex("1045")
    DATAFIELD = bytearray.fromhex("020000000000000000000000000000")
    END = bytearray.fromhex("15")
    counter = 0

    def __init__(self, modbus_frame, inverter_sn):
        type(self).counter += 1
        self.modbus_frame = modbus_frame.toBytes()
        self.inverter_sn = int(inverter_sn).to_bytes(4, "little")
        self.sn_prefix = int(type(self).counter).to_bytes(2, "big")
        
        self.update()
        
    def genCRC(self):
        checksum = 0
        for i in range(1, len(self.rawbytes) - 2, 1):
            checksum += self.rawbytes[i] & 255
        return int((checksum & 255))

    def update(self):
        self.length = (13 + len(self.modbus_frame) + 2).to_bytes(2, "little")  # datalength
        
        frame = (
        self.START
        + self.length
        + self.CONTROLCODE
        + self.sn_prefix
        + self.inverter_sn
        + self.DATAFIELD
        + self.modbus_frame
        + bytearray.fromhex("00") #self.genCRC()
        + self.END
        )
        
        self.rawbytes = frame
        self.rawbytes[len(self.rawbytes) - 2] = self.genCRC()
        
        return self
        
    def toBytes(self):
        return self.rawbytes

class rModbusResponse(NestedInformationGroup):
    name = "ModbusResponse"
    description = "Modbus Response Frame"
    parsemap = [rModbusCommand]
    values = {}
    
    modbus_parsemap = [
        sDeviceType,                                  # 000
        sModbusAddress,                               # 001   
        sComProtoVersion,                             # 002
        sSerial,                                      # 003
                                                      # 004
                                                      # 005
                                                      # 006
                                                      # 007
        "hex:16",                                     # 008
        "hex:16",                                     # 009
        "hex:16",                                     # 010
        "hex:16",                                     # 011
        "hex:16",                                     # 012
        "hex:16",                                     # 013
        "hex:16",                                     # 014
        "hex:16",                                     # 015
        sRatedPower,                                  # 016
                                                      # 017
        sNumMPPT, sNumPhases,                         # 018
        pRatedGridVoltage,                            # 019
        pRemoteLockEnabled,                           # 020
        pPostTime,                                    # 021
        pSystemTime,                                  # 022
                                                      # 023
                                                      # 024
        "hex:16",                                     # 025
        "hex:16",                                     # 026
        pGridVoltageUpperLimit,                       # 027
        pGridVoltageLowerLimit,                       # 028
        pGridFrequencyUpperLimit,                     # 029
        pGridFrequencyLowerLimit,                     # 030
        pGridCurrentUpperLimit,                       # 031
        "hex:16",                                     # 032
        "hex:16",                                     # 033
        "hex:16",                                     # 034
        "hex:16",                                     # 035
        "hex:16",                                     # 036
        "hex:16",                                     # 037
        "hex:16",                                     # 038
        "hex:16",                                     # 039
        pActivePowerRegulation,                       # 040
        "hex:16",                                     # 041
        "hex:16",                                     # 042
        pSwitchEnable,                                # 043
        pFactoryResetEnable,                          # 044
        pSelfCheckingTimeIsland,                      # 045
        pIslandProtectionEnable,                      # 046
        "hex:16",                                     # 047
        "hex:16",                                     # 048
        "hex:16",                                     # 049
        "hex:16",                                     # 050
        "hex:16",                                     # 051
        "hex:16",                                     # 052
        "hex:16",                                     # 053
        "hex:16",                                     # 054
        "hex:16",                                     # 055
        "hex:16",                                     # 056
        "hex:16",                                     # 057
        "hex:16",                                     # 058
        sRunState,                                    # 059
        sDayActivePower,                              # 060
        "hex:16",                                     # 061
        sUptime,                                      # 062
        sTotalActivePower,                            # 063
                                                      # 064
        sModule1DayActivePower,                       # 065
        sModule2DayActivePower,                       # 066
        sModule3DayActivePower,                       # 067
        sModule4DayActivePower,                       # 068
        sModule1TotalActivePower,                     # 069
                                                      # 070
        sModule2TotalActivePower,                     # 071
                                                      # 072
        sGridVoltage,                                 # 073
        sModule3TotalActivePower,                     # 074
                                                      # 075
        sGridCurrent,                                 # 076
        sModule4TotalActivePower,                     # 077
                                                      # 078
        sGridFrequency,                               # 079
        "hex:16",                                     # 080
        "hex:16",                                     # 081
        "hex:16",                                     # 082
        "hex:16",                                     # 083
        "hex:16",                                     # 084
        "hex:16",                                     # 085
        sActivePower,                                 # 086
                                                      # 087
        "hex:16",                                     # 088
        "hex:16",                                     # 089
        sTemperature,                                 # 090
        "hex:16",                                     # 091
        "hex:16",                                     # 092
        "hex:16",                                     # 093
        "hex:16",                                     # 094
        "hex:16",                                     # 095
        "hex:16",                                     # 096
        "hex:16",                                     # 097
        "hex:16",                                     # 098
        "hex:16",                                     # 099
        "hex:16",                                     # 100
        "hex:16",                                     # 101
        "hex:16",                                     # 102
        "hex:16",                                     # 103
        "hex:16",                                     # 104
        "hex:16",                                     # 105
        "hex:16",                                     # 106
        "hex:16",                                     # 107
        "hex:16",                                     # 108
        sModule1Voltage,                              # 109
        sModule1Current,                              # 110
        sModule2Voltage,                              # 111
        sModule2Current,                              # 112
        sModule3Voltage,                              # 113
        sModule3Current,                              # 114
        sModule4Voltage,                              # 115
        sModule4Current,                              # 116
        "hex:16",                                     # 117
        "hex:16",                                     # 118
        "hex:16"                                      # 119
        ]                                       
                                                      
    def __init__(self, data=None):                    
        self.unparsed = bytes()                       
        if data is not None:
            start = data.bytepos
            i = 0
            for p in self.parsemap:
                try:
                    if isinstance(p, str):
                        pad = data.read(p)
                        self.values[f"UNPARSED_{i}"] = pad
                    else:
                        self.values[p.name] = p(data)
                except:
                    pass
                
                if i==0:
                    if self.values[p.name].value == ModbusRequest.DEYE_READ:
                        self.parsemap.append(rModbusLength)

                if i==1:
                    self.length = self.values[p.name].value
                    if self.length > 0:
                        self.parsemap += self.modbus_parsemap
                    self.parsemap.append(rModbusCRC)
                    
                i+=1
                    
            self.rawdata = data.bytes[start:data.bytepos]

class DeyeTCPResponse(InformationGroup):
    name = "DeyeTCPResponse"
    description = "Deye TCP Response Frame"
    parsemap = [rDeyeStart, rLength, rControlCode, rFrameNum, rInvSerial, "hex:112", rModbusResponse, rDeyeCRC, rDeyeEnd]
    values = {}


def main():
    if len(sys.argv) == 2 and ":" in sys.argv[1]:
        ip,port = sys.argv[1].split(":")
        tcp = TransportTCP(ip, int(port))
        tcp.start()

        frame_bytes = DeyeTCPRequest(ModbusRequest(ModbusRequest.DEYE_READ, 0, 1), "0000000000").toBytes()
        response = tcp.send(frame_bytes)
        deyeTCPResponse = DeyeTCPResponse(response)
        invSerial = deyeTCPResponse.values["InvSerial"].value
        print(F"[+] Connected to Inverter with Serial: {invSerial}")
        

        frame_bytes = DeyeTCPRequest(ModbusRequest(ModbusRequest.DEYE_READ, 0, 120), invSerial).toBytes()
        response = tcp.send(frame_bytes)
        print(response.hex())
        deyeTCPResponse = DeyeTCPResponse(response)
        deyeTCPResponse.values["ModbusResponse"].values = {k: v for k, v in deyeTCPResponse.values["ModbusResponse"].values.items() if "UNPARSED" not in k and "3" not in k and "4" not in k}
        print(deyeTCPResponse.values["ModbusResponse"])
    else:
        print("Usage: ./deye.py ip:port\nPort is likely 8899")

if __name__ == '__main__':
    main()
'''
a5 1700 1045 0000 11fac1ec 02 0000000000000000000000000000 0103 003c 0001 4406 b1 15
a5 1500 1015 0030 11fac1ec 02 0116d703004e06000000000000 0103 0200 6d79 a9fe 15
a5 1500 1015 0031 11fac1ec 02 0117d703004f06000000000000 0103 0200 6d79 a901 15
a5 1500 1015 0032 11fac1ec 02 0119d703005006000000000000 0103 0200 6d79 a905 15
a5 1500 1015 0033 11fac1ec 02 011ad703005206000000000000 0103 0200 6d79 a909 15
a5 1700 1015 0001 11fac1ec 02 013bd903007101000000000000 0103 0400 6e00 009b ee80 15
a5 1900 1015 0002 11fac1ec 02 0135db03006b03000000000000 0103 0600 6e00 0000 00c8 bc78 15
a5 1000 1015 001b 11fac1ec 02 019dfe0300c803000000000000 0600 7a 15
'''
