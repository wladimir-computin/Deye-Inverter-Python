# Deye Inverter Python 
 
Read/Write information from Deye microinverters using Python. 

Direct communication via Modbus. No Clouds.

## Usage
 
```bash
./deye.py 192.168.178.xx:8899


[+] Connected to Inverter with Serial: 3xxxxxxxxx
a503011015000811fac1ec020100f14500e4050000000000000103f00004010003023233313131353034433600010000120c070001030301132200001f4000000201004b0000004130000000000001b0000c0b3b0730141e128e09e2040b0001139c00280000139c006407d00064000000000001000100080001000100000001ff010002000a00000000270200000000000000020183000000000bc5000000a1009c0000000005c5000005bb0000091a00000000000000000000138800000000000000000000000000da0000000000000b2209470947138700000000000000000000000004910000001d00000000000000000000000001480003013600040000000000000000014801400000fa886315
Name: ModbusResponse
Modbus Response Frame
 ModbusCommand: 0103
 ModbusLength: 240
 sDeviceType: 0004
 sModbusAddress: 1
 sComProtoVersion: b'\x03\x02'
 sSerial: b'23xxxxxxxx'
 sRatedPower: : 800.0W
 sNumMPPT: 2
 sNumPhases: 1
 pRatedGridVoltage: 004b
 pRemoteLockEnabled: 0
 pPostTime: 65s
 pSystemTime: 300000000000
 pGridVoltageUpperLimit: 287.5V
 pGridVoltageLowerLimit: 184.0V
 pGridFrequencyUpperLimit: 51.5Hz
 pGridFrequencyLowerLimit: 47.5Hz
 pGridCurrentUpperLimit: 253.0A
 pActivePowerRegulation: 100%
 pSwitchEnable: 1
 pFactoryResetEnable: 1
 pSelfCheckingTimeIsland: 8s
 pIslandProtectionEnable: 1
 sRunState: 2
 sDayActivePower: 38.7kWh
 sUptime: 0min
 sTotalActivePower: : 301.3kWh
 sModule1DayActivePower: 16.1kWh
 sModule2DayActivePower: 15.6kWh
 sModule1TotalActivePower: : 147.7kWh
 sModule2TotalActivePower: : 146.7kWh
 sGridVoltage: 233.0V
 sGridCurrent: 0.0A
 sGridFrequency: 50.0Hz
 sActivePower: : 21.8W
 sTemperature: 28.5°C
 sModule1Voltage: 32.8V
 sModule1Current: 0.3A
 sModule2Voltage: 31.0V
 sModule2Current: 0.4A
 ModbusCRC: fa88
``` 
