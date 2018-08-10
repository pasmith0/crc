#!/usr/bin/env python3
""" 
@copyright  Copyright (c) 2017 Nuvectra. All rights reserved.
@license    Confidential & Proprietary
"""

""" 
@brief      Provides a wrapper around bincopy python lib, which is
            used to get addresses and data from .s28 files.
"""

import sys
import os
import bincopy
from operator import itemgetter
from itertools import groupby, chain
from random import shuffle
import struct
import collections

import logging
log = logging.getLogger(__name__)

class Srec:
    """
    Class for handling .s28 files.
    Contains functions for crc checks as well.

    The bincopy module will check all the lines in the srec to ensure that 
    they are valid.
    """

    def __init__(self, filename):
        """ 
        Loads in srec file.
        Tests all crcs and verifies that the format is valid.
        """
        self.record = bincopy.BinFile()
        if filename is not None:
            self.record.add_srec_file(filename)

        # static var ranges
        self.ranges=dict()

        self.Range = collections.namedtuple('Range', 'min max')
        #
        # "BL_..." addresses are copied directly from the bootloader code.
        self.ranges["BL_VALID_INFO_MEMORY"]      = self.Range(min=0x1000, max=0x10FF )
        self.ranges["BL_VALID_RAM"]              = self.Range(min=0x1100 ,max=0x30FF )
        self.ranges["BL_VALID_LOW_MEMORY"]       = self.Range(min=0x7000 ,max=0xFFBF )
        self.ranges["BL_VALID_LOW_CODE_MEMORY"]  = self.Range(min=0x9000 ,max=0xFDFF )
        self.ranges["BL_VALID_HIGH_CODE_MEMORY"] = self.Range(min=0x10000,max=0x1F3FF)
        self.ranges["BL_VALID_HIGH_DATA_MEMORY"] = self.Range(min=0x1F400,max=0x1FFFF)

        self.ranges["BL_VALID_INFO_MEMORY_D"] = self.Range(min=0x1000,max=0x103F)
        self.ranges["BL_VALID_INFO_MEMORY_C"] = self.Range(min=0x1040,max=0x107F)
        self.ranges["BL_VALID_INFO_MEMORY_B"] = self.Range(min=0x1080,max=0x10BF)
        self.ranges["BL_VALID_INFO_MEMORY_A"] = self.Range(min=0x10C0,max=0x10FF)

        # This is for the lowermost and uppermost special case addresses
        # see also extractSpecialAddresses
        self.ranges["SPECIAL_CASES"] = self.Range(min=0xFFDC,max=0xFFFE)

        #
        self.ranges["VALID_INFO_MEMORY"]      = self.Range(min=0x1000,max=0x10FF )
        self.ranges["VECTOR_TABLE"]           = self.Range(min=0xFFC0,max=0xFFFF )

        self.ranges["VALID_LOW_CODE_MEMORY"]  = self.Range(min=0x9000 ,max=0xFDFF )
        self.ranges["VALID_LOW_MEMORY"]       = self.Range(min=0x7000 ,max=0xFFBF )
        self.ranges["VALID_HIGH_CODE_MEMORY"] = self.Range(min=0x10000,max=0x20000)

        ############
        # Stuff from xpg loader.
        # This might all be garbage, keeping around until tests completed.

        #self.ranges["VALID_LOW_CODE_MEMORY"]  = (0x9000 ,0xFDFF)
        ## This one from xpg loader?
        #self.ranges["VALID_HIGH_CODE_MEMORY"] = (0x10000 ,0x20000)

        #self.ranges["VALID_LOW_MEMORY"]       = (0x7000 ,0xFFBF )
        ##self.ranges["VALID_HIGH_CODE_MEMORY"] = (0x10000,0x1F3FF)
        #self.ranges["VALID_HIGH_DATA_MEMORY"] = (0x1F400,0x1FFFF)
        #self.ranges["VALID_INFO_MEMORY"]      = (0x1000 ,0x10FF )
        #self.ranges["VALID_RAM"]              = (0x1100 ,0x30FF )

        #self.ranges["PROGRAM_SPACE"]          = (0x3100 ,0x19FFF )



        """
        For crc16 calculation - see also XPG Bootloader code flash.h/c.
        Table for x^16 + x^15 + x^2 + x^0 CRC-16-IBM.
        """
        self.crcTable = [
            0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
            0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
            0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
            0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
            0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
            0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
            0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
            0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
            0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
            0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
            0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
            0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
            0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
            0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
            0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
            0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
            0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
            0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
            0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
            0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
            0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
            0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
            0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
            0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
            0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
            0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
            0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
            0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
            0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
            0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
            0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
            0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040 ]


    def getAddressRanges(self):
        """ 
        Returns a list of NamedTuple with the form
        collections.namedtuple('Range', 'min max')
        """
        ranges=list()
        for address, data in self.record.segments:
            minimum_address = (address)
            maximum_address = (minimum_address
                               + len(data))
            ranges.append( self.Range(min=minimum_address,
                                      max=maximum_address) )
            log.info("%08x-%08x" % ranges[-1])

        return ranges


    def getExactRanges(self, srecDataList):
        """
        return - A list of tuples containing a range for each group of contiguous 
                 address group in srecDataList. Ranges are inclusive.

                 See getSrecData().
        """
        addresses=list()
        # Extract each individual address contained in the srecord.
        for addr, barray in srecDataList:
            if self.isAddressValidForBootloaderWrite(int(addr,16)):
                for i in range(0,len(barray)):
                    addresses.append(int(addr,16)+i)

        # Use the above list to figure out exact address ranges for 
        # groups of contiguous addresses.
        groups=list()
        for key, group in groupby(enumerate(addresses), lambda i: i[0] - i[1]):
            group = list(map(itemgetter(1), group))
            groups.append(self.Range(min=group[0], max=group[-1]))

        return groups


    def getSrecData(self):
        """
        Returns a list of tuples in form [namedtuple('SrecData', 'addr_str byte_array')].
        Where addr_str is a string of the address in hex
        and byte_array is a bytearray of the data that start @ addr_str

            For example:
            test = Srec('./ipg_r1.02.0002.s28')

            for address, b_array in test.getSrecData():
                print(address,end=":")
                print(b_array)
        """
        dump=self.record.as_hexdump()
        return self.processHexDump(dump)


    @staticmethod
    def processHexDump(dump):
        """ 
        Helper function for getSrecData().
        Should be called through getSrecData().

        NOTE: this should use srecord segments property instead or parsing
              output
        """
        list_of_tuples=list()
        SrecData = collections.namedtuple('SrecData', 'addr_str byte_array')

        # e.g. 0001d900  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        for line in dump.splitlines():
            if not line[0].isdigit():
                continue

            # Chop off "|................|".
            line = line.split('|')[0]
            #print(line)

            # Grab address "0001d900".
            address = line.split()[0]

            # Grab data bytes "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00".
            #print("".join(line.split()[1:]))
            data_array = bytearray.fromhex("".join(line.split()[1:]))

            # Make into tuple and add to list.
            list_of_tuples.append(
                SrecData(addr_str=address, byte_array=data_array))

        return list_of_tuples


    @staticmethod
    def isRangeOverlap(x1,x2,y1,y2):
        """
        Returns True if two ranges, [x1,x2] and [y1,y2], have overlap.
        Otherwise, returns False.
        Note that x1 <= x2 and y1 <= y2 is required.
        x1 <= y2 && y1 <= x2
        """
        assert x1 <= x2
        assert y1 <= y2
        if(x1 <= y2 and y1 <= x2):
            return True
        return False


    def isAddressValidForBootloaderWrite(self,address_int):
        """
        Returns True if an address is in either low code or high code range.
        Otherwise, returns False.
        """
        if self.isInRange(address_int,
                          address_int,
                          self.ranges["VALID_LOW_MEMORY"].min,
                          self.ranges["VALID_HIGH_CODE_MEMORY"].max
                          ):
            return True
        return False


    def isHasInfoMemory(self, low, high):
        """
        Returns True if a range, [low,high], overlaps the BL_VALID_INFO_MEMORY
        range.
        Otherwise, returns False.
        """
        return self.isRangeOverlap(low,
                                   high,
                                   self.ranges["BL_VALID_INFO_MEMORY"].min,
                                   self.ranges["BL_VALID_INFO_MEMORY"].max)


    def isInRange(self,x1,x2,y1,y2):
        """
        Returns True if a range, [x1,x2], is completely contained within
        a second range, [y1,y2].
        Otherwise, returns False.
        Note that x1 <= x2 and y1 <= y2 is required.
        """
        assert x1 <= x2
        assert y1 <= y2
        if( y1 <= x1 <= y2
           and y1 <= x2 <= y2):
            return True
        return False


    def getListForVectorCRC(self):
        """
        Returns a list of vector values in the correct order for use in 
        application crc calculations.
        """
        dataList = self.getSrecData()

        vectorTableBasesDict=dict() # key -- address as int
                                    # value -- byte array starting at key

        # Srecords come in 16 byte blocks so get anything that could contain
        # even 1 byte in the vector table address space.
        for item in dataList:
            address_int=int(item.addr_str,16)
            if self.isInRange(address_int,
                              address_int,
                              self.ranges["VECTOR_TABLE"].min,
                              self.ranges["VECTOR_TABLE"].max):

                vectorTableBasesDict[address_int]=item.byte_array

        # Force it to be sorted, since order matters.
        vectorTableBasesDict =  collections.OrderedDict(
            sorted(vectorTableBasesDict.items()))

        subBytes=dict() # Hold the byte by byte breakout of vectorTableBasesDict.
                        # key -- exact address of the byte 
                        # value -- the value of that byte
        # Get the byte by byte breakout of all sub-addresses between 0xFFDC and
        # the end of the vector table (except the last two bytes).
        for adr_int,barray in vectorTableBasesDict.items():
            for i,byte in enumerate(barray):
                sub_address = adr_int+i

                # Ignore last two bytes since they are not used in the crc 
                # calculation, they are for the boot vector.
                if sub_address >= 0xFFDC and \
                   sub_address <= self.ranges["VECTOR_TABLE"].max - 2:
                    subBytes[sub_address]=byte

        # Ensure we maintain order.
        subBytes = collections.OrderedDict(sorted(subBytes.items()))

        # Convert to a list.
        orderedVectorValues4crc=list()
        for adr_int, val in subBytes.items():
            orderedVectorValues4crc.append(val)

        return orderedVectorValues4crc


    def getCRC(self):
        """
        Calculates and returns the CRC for the application based on the srecord.
        """
        dataList = self.getSrecData()

        vectorTable_list = self.getListForVectorCRC()

        crc = 0xffff # initial seed mask

        # First is low code crc.
        #
        # Grab all bytes in the low code/mem area and feed it into the crc,
        # byte by byte.
        for adr_str, barray in dataList:
            adr_int = int(adr_str,16)
            for j, byte in enumerate(barray):
                if self.isInRange(adr_int+j,
                            adr_int+j,
                            self.ranges["BL_VALID_LOW_MEMORY"].min,
                            self.ranges["BL_VALID_LOW_CODE_MEMORY"].max):

                    crc = self.computeCRC16(crc, [byte])
        #print("for 1.02.002 i would be 0xCDDF at this point. I am: %04x" % crc)

        # Next up is the vector table.
        #
        crc = self.computeCRC16(crc,vectorTable_list)
        #print("for 1.02.002 i would be 0x0A4E at this point. I am: %04x" % crc)


        # Finally, go through the high code/mem area.
        #
        for adr_str, barray in dataList:
            adr_int = int(adr_str,16)

            for j, byte in enumerate(barray):
                if self.isInRange(adr_int+j,
                            adr_int+j,
                            self.ranges["BL_VALID_HIGH_CODE_MEMORY"].min,
                            self.ranges["BL_VALID_HIGH_DATA_MEMORY"].max):
                    crc = self.computeCRC16(crc, [byte])
        #print("for 1.02.002 i would be 0xCDCF for the final crc. I am: %04x" % crc)

        return crc


    def computeCRC16(self, seed, inputArray):
        """
        Calculates and returns the crc16. See also XPG Bootloader code flash.h/c.
        """
        crc16 = seed

        for byte in inputArray:
            crc16 = (self.crcTable[(crc16 & 0xFF) ^ byte]) ^ (crc16 >> 8)

        return crc16


    def extractSpecialAddresses(self, address_data_pairs):
        """
        The addresses in the range [0xFFFE, 0XFFDC] are special cases.
        They will be removed from address_data_pairs and returned as a dict.

            address_data_pairs -- See getSrecData() return type.
            return -- Dictionary of special cases.
        """
        special_cases = list()
        special_cases_dict = dict()

        for item in address_data_pairs:

            try:
                address_int = int(item.addr_str,16) #< Convert from hex string.
            except:
                print("can not process \"%s\"" % item.addr_str)

            if self.isRangeOverlap(address_int,
                                address_int,
                                self.ranges["VECTOR_TABLE"].min,
                                self.ranges["VECTOR_TABLE"].max):
                special_cases.append(item.addr_str)

            get2bytes = lambda b,i: int.from_bytes(b[i:i+2], byteorder='little', signed=False)

            # Loop by groups of 2 bytes.
            for i in range(0, len(item.byte_array), 2):
                currentByte = get2bytes(item.byte_array,i)

                if address_int+i == 0xFFFE:
                    special_cases_dict["entry_point"] = currentByte
                if address_int+i == 0xFFFC:
                    special_cases_dict["NMI"] = currentByte
                if address_int+i == 0xFFFA:
                    special_cases_dict["Timer_B7_TBCCR0"] = currentByte
                if address_int+i == 0xFFF8:
                    special_cases_dict["Timer_B7_TBCCR1_TBCCR6_TBIFG"] = currentByte
                if address_int+i == 0xFFF6:
                    special_cases_dict["Comparator_A"] = currentByte
                if address_int+i == 0xFFF4:
                    special_cases_dict["Watchdog_Timer"] = currentByte
                if address_int+i == 0xFFF2:
                    special_cases_dict["Timer_A3_TACCRO"] = currentByte
                if address_int+i == 0xFFF0:
                    special_cases_dict["Timer_A3_TACCR1_TACCR2_TAIFG"] = currentByte
                if address_int+i == 0xFFEE:
                    special_cases_dict["USCI_A0_USCI_B0_receive"] = currentByte
                if address_int+i == 0xFFEC:
                    special_cases_dict["USCI_A0_USCI_B0_transmit"] = currentByte
                if address_int+i == 0xFFEA:
                    special_cases_dict["ADC12"] = currentByte
                if address_int+i == 0xFFE8:
                    special_cases_dict["unused"] = currentByte
                if address_int+i == 0xFFE6:
                    special_cases_dict["I_O_Port_P2"] = currentByte
                if address_int+i == 0xFFE4:
                    special_cases_dict["I_O_Port_P1"] = currentByte
                if address_int+i == 0xFFE2:
                    special_cases_dict["USCI_A1_USCI_B1_receive"] = currentByte
                if address_int+i == 0xFFE0:
                    special_cases_dict["USCI_A1_USCI_B1_transmit"] = currentByte
                if address_int+i == 0xFFDE:
                    special_cases_dict["DMA"] = currentByte
                if address_int+i == 0xFFDC:
                    special_cases_dict["DAC12"] = currentByte

        # Remove all special cases, using list comprehensions.
        check_for_remove_func = lambda x: (x[0] in special_cases)
        address_data_pairs[:] = [x for x in address_data_pairs if not check_for_remove_func(x)]

        return special_cases_dict
