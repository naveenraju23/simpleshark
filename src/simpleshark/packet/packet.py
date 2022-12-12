from simpleshark.packet import consts
import datetime


class Packet(object):
    """
    A packet object which contains layers.
    Layers can be accessed via index or name.
    """

    def __init__(self, protos, geninfo, frame):
        """
        Creates a Packet object with the given layers and info.

        :param protos: A list of protocol objects.
        :param frame: A frame protocol object
        :param geninfo: A general information protocol object for the entire packet frame (information like frame length, packet number, etc.
        :param number: Packet number in the capture
        :param length: Length of the actual packet.
        :param captured_length: The length of the packet that was actually captured (could be less then length)
        :param sniff_time: The time the packet was captured (timestamp)
        :param interface_captured: The interface the packet was captured in.
        """
        self.protos = protos
        self.geninfo = geninfo
        self.frame = frame
        self.number = geninfo.get_field_value('num')
        self.interface_captured = frame.get_field_value('interface_id')
        self.captured_length = geninfo.get_field_value('caplen')
        self.length = geninfo.get_field_value('len')
        self.timestamp = geninfo.timestamp

    def __repr__(self):
        transport_protocol = ''
        if self.transport_layer != self.highest_layer and self.transport_layer is not None:
            transport_protocol = self.transport_layer + '/'

        return '<%s%s Packet>' % (transport_protocol, self.highest_layer)

    def __contains__(self, proto):
        """
        Checks if the protocol is inside the packet.

        :param proto: name of the protocol
        """
        try:
            self[proto]
            return True
        except KeyError:
            return False

    def __getitem__(self, item):
        """
        Gets a layer according to its index or its name

        :param item: layer index or name
        :return: Layer object.
        """
        if isinstance(item, int):
            return self.protos[item]
        for proto in self.protos:
            if proto.name == item.lower():
                return proto
        raise KeyError('Protocol does not exist in packet')

    def __getattr__(self, item):
        """
        Allows layers to be retrieved via get attr. For instance: pkt.ip
        """
        _protos = []
        for proto in self.protos:
            if proto.name == item:
                _protos.append(proto)
        if not _protos:
            raise AttributeError("No attribute named %s" % item)

        if len(_protos) > 1:
            return _protos
        else:
            return _protos[-1]

    @property
    def sniff_timestamp(self):
        try:
            timestamp = float(self.timestamp.raw)
        except ValueError:
            # If the value after the decimal point is negative, discard it
            # Google: wireshark fractional second
            timestamp = float(self.timestamp.raw.split(".")[0])
        return datetime.datetime.fromtimestamp(timestamp)

    @property
    def highest_layer(self):
        """
        Returns the name of the highest layer protocol.
        """
        return self.protos[-1].name.upper()

    @property
    def transport_layer(self):
        for layer in consts.TRANSPORT_LAYERS:
            if layer in self:
                return layer

