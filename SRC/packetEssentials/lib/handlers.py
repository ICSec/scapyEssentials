import collections
import signal
import sys
from scapy.layers.dot11 import Dot11
from scapy.utils import wrpcap

class Handlers(object):
    """Useful packet handlers

    Requires utils Class object as a parameter for Instantiation
    """
    def __init__(self, util):
        self.envTrafficCount = 0
        self.mpTrafficList = []
        self.mpTrafficCount = 0
        self.mpTrafficHit = 0
        self.soloList = []
        self.soloCount = 0
        self.soloHit = 0
        self.util = util
        self.metaMode = None
        self.metaCounts = {}
        self.metaSums = {}
        self.handler = None
        self.handlerDict = {'mpTraffic': self.mpTrafficList,
                            'soloTraffic': self.soloList}

        ## ADD SIGNAL HANDLER
        self.signal_handler = self.crtlC()
        signal.signal(signal.SIGINT, self.signal_handler)


    def crtlC(self):
        """Handles what happens when crtl + c occurs
        Tries to deal with unexpected situations in which the collected lists are at
        risk of being lost
        """
        def tmp(signal, frame):
            if self.handler is not None:
                print ('\n [!] Saving {0} frames --> {1}'.format(len(self.handlerDict.get(self.handler)), self.handler + '.pcap\n'))
                wrpcap(self.handler + '.pcap', self.handlerDict.get(self.handler))
            print('\n\n [!] Crtl + C sequence complete\n')
            sys.exit(0)
        return tmp


    def metaDisplay(self, orderHigh = True):
        """Returns self.metaCounts and self.metaSums as sorted lists
        The default is to return based on the value order of highest to lowest
        This is useful with regards to 802.11 in general.

        If a NIC is in range:
            - The RSSI for a given frame, at a particular point in space,
            relative to the location of the device in earshot can be considered
            the relative volume of the conversation.

            - The quantity of frames can be considered a metric of how chatty a
            given NIC is.

            - The sum of bytes transferred can be a metric in ratio to quantity,
             and other such things.  Logarithmic graphing helps in this respect.
        """
        metaCounts = collections.OrderedDict()
        metaSums = collections.OrderedDict()
        for k, v in sorted(self.metaCounts.items(), key = lambda item: item[1], reverse = orderHigh):
            metaCounts.update({k: v})
        for k, v in sorted(self.metaSums.items(), key = lambda item: item[1], reverse = orderHigh):
            metaSums.update({k: v / 1024})
        return metaCounts, metaSums


    def mpTrafficCap(self, macX, macY, q = False, verbose = False):
        """Packet handler to follow a given pair of MAC addresses
        Uses macPair as a boolean wrapper to determine if both MACs were seen
        Captures self.mpTrafficList
        """
        self.handler = 'mpTraffic'
        self.verbose = verbose
        if q is not False:
            qty = int(q)
        def snarf(pkt):

            ## No count qty
            if q is False:

                if self.util.macPair(macX, macY, pkt) is True:
                    self.mpTrafficList.append(pkt)
                    self.mpTrafficHit += 1
                    r = True
                else:
                    r = False

                if verbose is True:
                    print('{0} -- '.format(r) + str(self.mpTrafficCount) + '--' + str(self.mpTrafficHit))

            ## Count qty
            else:
                if self.mpTrafficHit < qty:
                    if self.util.macPair(macX, macY, pkt) is True:
                        self.mpTrafficList.append(pkt)
                        self.mpTrafficHit += 1
                        r = True
                    else:
                        r = False
                    if verbose is True:
                        print('{0} -- '.format(r) + str(self.mpTrafficCount) + '--' + str(self.mpTrafficHit))
                else:
                    wrpcap('mpTraffic.pcap', self.mpTrafficList)
                    sys.exit(0)
            self.mpTrafficCount += 1
        return snarf


    def soloCap(self, macX, q = False, verbose = False):
        """Packet handler to follow a given pair of MAC addresses
        Uses macFilter as a boolean wrapper to determine if both MACs were seen
        Captures self.soloList
        """
        self.handler = 'soloTraffic'
        self.verbose = verbose
        if q is not False:
            qty = int(q)
        def snarf(pkt):

            ## No count qty
            if q is False:

                if self.util.macFilter(macX, pkt) is True:
                    self.soloList.append(pkt)
                    self.soloHit += 1
                    r = True
                else:
                    r = False

                if verbose is True:
                    print('{0} -- '.format(r) + str(self.soloCount) + '--' + str(self.soloHit))

            ## Count qty
            else:
                if self.soloHit < qty:
                    if self.util.macFilter(macX, pkt) is True:
                        self.soloList.append(pkt)
                        self.soloHit += 1
                        r = True
                    else:
                        r = False

                    if verbose is True:
                        print('{0} -- '.format(r) + str(self.soloCount) + '--' + str(self.soloHit))
                else:
                    wrpcap('solo.pcap', self.soloList)
                    sys.exit(0)
            self.soloCount += 1
        return snarf
