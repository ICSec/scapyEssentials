from .converter import Converter

from scapy.layers.dot11 import Dot11
from scapy.utils import hexstr, PcapReader, PcapWriter, rdpcap, wrpcap
from scapy.plist import PacketList
from zlib import crc32
import binascii
import sys

class Poption(object):
    """Class to deal with packet specific options"""

    def __init__(self):
        self.nonceDict = {'8a': 'a1',
                          '0a': 'a2',
                          'ca': 'a3',
                          '89': 't1',
                          '09': 't2',
                          'c9': 't3'}
        self.verbose = False
        self.cv = Converter()


    def byteRip(self,
                stream,
                chop = False,
                compress = False,
                order = 'first',
                output = 'hex',
                qty = 1):
        """Take a packet and grab a grouping of bytes, based on what you want

        byteRip can accept a scapy object or a scapy object in str() format
        Allowing byteRip to accept str() format allows for byte insertion

        Example of scapy object definition:
          - stream = Dot11WEP()

        Example of scapy object in str() format
          - stream = str(Dot11WEP())

        chop is the concept of removing the qty based upon the order
        compress is the concept of removing unwanted spaces
        order is concept of give me first <qty> bytes or gives me last <qty> bytes
        output deals with how the user wishes the stream to be returned
        qty is how many bytes to remove
        """

        def pktFlow(pkt, output):
            if output == 'hex':
                return pkt
            if output == 'str':
                return binascii.unhexlify(str(pkt).replace(' ', ''))

        ## Python 2x and 3x seem to align on this method now
        # stream = hexstr(str(stream), onlyhex = 1)
        stream = hexstr(stream, onlyhex = 1)
        streamList = stream.split(' ')
        streamLen = len(streamList)

        ## Deal with first bytes
        if order == 'first':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[0:qty]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[qty:]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[0:qty]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[qty:]).replace(' ', ''), output)

        ## Deal with last bytes
        if order == 'last':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[streamLen - qty:]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[:-qty]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[streamLen - qty:]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[:-qty]).replace(' ', ''), output)


    def endSwap(self, value):
        """Takes an object and reverse Endians the bytes

        Useful for crc32 within 802.11:
        Autodetection logic built in for the following situations:
        Will take the stryng '0xaabbcc' and return string '0xccbbaa'
        Will take the integer 12345 and return integer 14640
        Will take the bytestream string of 'aabbcc' and return string 'ccbbaa'
        """
        try:
            value = hex(value).replace('0x', '')
            sType = 'int'
        except:
            if '0x' in value:
                sType = 'hStr'
            else:
                sType = 'bStr'
            value = value.replace('0x', '')

        start = 0
        end = 2
        swapList = []
        # print(value)
        # for i in range(len(value) / 2):
        for i in range(int(len(value) / 2)):  # Python3x compat.
            swapList.append(value[start:end])
            start += 2
            end += 2
        swapList.reverse()
        s = ''
        for i in swapList:
            s += i

        if sType == 'int':
            s = int(s, 16)
        elif sType == 'hStr':
            s = '0x' + s
        return s


    def fcsGen(self,
               frame,
               start = None,
               end = None,
               mLength = 0,
               output = 'bytes'):
        """Return the FCS for a given frame

        MODIFYING THIS PROBABLY BREAKS OTHER THINGS

        Where objFrame is the frame
        x = hexstr(objFrame, onlyhex = 1).replace(' ', '').lower()
        crc32(binascii.unhexlify(x.replace(' ', '')))

        """
        ## Original Python2x way of doing it -- when str(frame) worked nicely...
        # frame = str(frame)
        # frame = frame[start:end]
        # frame = crc32(frame) & 0xffffffff

        ## Python 2x or 3x way
        # frame = str(frame)  ## As we're using the raw object to get to 2x str() format, this is no longer needed
        frame = frame[start:end]
        frame = hexstr(frame, onlyhex = 1).replace(' ', '').lower()
        frame = crc32(binascii.unhexlify(frame.replace(' ', ''))) & 0xffffffff

        fcs = hex(frame).replace('0x', '')
        while len(fcs) < mLength:
            fcs = '0' + fcs
        fcs = self.endSwap(fcs)
        if output == 'bytes':
            return fcs
        elif output == 'str':
            return binascii.unhexlify(fcs)
        else:
            return fcs


    def macFilter(self, mac, pkt):
        """ Combo whitelist and blacklist for given MAC address """
        try:
            ## Get state
            if pkt[Dot11].addr1 == mac or pkt[Dot11].addr2 == mac or pkt[Dot11].addr3 == mac or pkt[Dot11].addr4 == mac:
                match = True
            else:
                match = False
            return match
        except:
            return False


    def macPair(self, macX, macY, pkt):
        """Pair up the MAC addresses, and follow them

        macX is weighted before macY, allowing the user to have a ranked format
        For fastest results, use macX as the quietest MAC
        """
        if self.macFilter(macX, pkt) is True:
            if self.macFilter(macY, pkt) is True:
                return True
        return False


    def symStryngs(self, scpObj, fld, maxInt = 254):
        """Iterator to show the available opcodes for a given scapy object
        Returns a list object by default of 0-253 for the opcode
        """
        count = 0
        scpObj = scpObj.copy()
        scpObj.setfieldval(fld, count)
        strDict = {}
        while count < maxInt:
            strDict.append({count: self.cv.symString(scpObj, fld)})
            count += 1
            try:
                scpObj.setfieldval(fld, count)
            except Exception as e:
                print(str(e) + ' -- Stopped on {0}'.format(count))
        return strDict
