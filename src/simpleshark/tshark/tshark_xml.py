"""This module contains functions to turn TShark XML parts into Packet objects."""
import lxml.objectify

from simpleshark.packet.fields import Field
from simpleshark.packet.packet import Packet
from simpleshark.packet.packet_summary import PacketSummary


def psml_structure_from_xml(psml_structure):
    if not isinstance(psml_structure, lxml.objectify.ObjectifiedElement):
        psml_structure = lxml.objectify.fromstring(psml_structure)
    return psml_structure.findall('section')


def packet_from_xml_packet(xml_pkt, psml_structure=None):
    """
    Gets a TShark XML packet object or string, and returns a Packet object.

    :param xml_pkt: str or xml object.
    :param psml_structure: a list of the fields in each packet summary in the psml data. If given, packet will
    be returned as a PacketSummary object.
    :return: Packet object.
    """
    if not isinstance(xml_pkt, lxml.objectify.ObjectifiedElement):
        parser = lxml.objectify.makeparser(huge_tree=True)
        xml_pkt = lxml.objectify.fromstring(xml_pkt, parser)
    if psml_structure:
        return _packet_from_psml_packet(xml_pkt, psml_structure)
    return _packet_object_from_xml(xml_pkt)


def _packet_from_psml_packet(psml_packet, structure):
    return PacketSummary(structure, psml_packet.findall('section'))


def _packet_object_from_xml(xml_pkt):
    protos = [Field(x, 'Proto') for x in xml_pkt.proto]
    return Packet(protos[2:], protos[0], protos[1])
