#!/usr/bin/env python3

import socket
import struct
import os
import pcapy
import logging
import argparse

VETH_MTU = 10240

logger = logging.getLogger()


class VxlanDecap(object):
    def __init__(self, veth_base, mirror_iface, destroy_on_exit=None, filter=None):
        self.destroy = destroy_on_exit
        self.filter = filter

        self.create_veth_pair(f"{veth_base}_in", f"{veth_base}_out")
        self.capture = self.open_tap_iface(mirror_iface, filter=filter)
        self.mirror_iface = mirror_iface

        # Open a raw socket to send packets
        self.raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.raw.bind((self.veth_in, 0))

    def __del__(self):
        if self.destroy:
            self.destroy_veth_pair(self.veth_in)

    def create_veth_pair(self, in_name, out_name):
        iflist = pcapy.findalldevs()

        new_in = None
        new_out = None

        for iface in iflist:
            if iface == in_name:
                new_in = iface
            if iface == out_name:
                new_out = iface

        if not new_in and not new_out:
            logger.info("Creating veth interface pair {in_name} and {out_name}")
            os.system(
                f"ip link add {in_name} type veth peer name {out_name} mtu {VETH_MTU}"
            )
            os.system(f"ip link set dev {in_name} up")
            os.system(f"ip link set dev {out_name} up")
            if self.destroy is None:
                self.destroy = True

        else:
            logger.warning(f"assuming {in_name} and {out_name} are properly configured")
            if self.destroy is None:
                self.destroy = False

        self.veth_in = new_in
        self.veth_out = new_out

    @staticmethod
    def destroy_veth_pair(in_name):
        os.system(f"ip link del {in_name}")

    @staticmethod
    def open_tap_iface(ifname, filter):
        # FIXME: what does to_ms mean?
        if ifname.endswith(".pcap"):
            p = pcapy.open_offline(ifname)
        else:
            p = pcapy.open_live(ifname, VETH_MTU, True, 10)
        if filter:
            p.setfilter(filter)
        else:
            logger.warning("No pcap filter set -- this is likely to break")

        return p

    def send_raw(self, data):
        self.raw.send(data)

    def handle_packet(self, hdr, data):
        start_offset = 14

        # ethertype
        ethertype_info = struct.unpack("!HHH", data[12:18])
        ethertype = ethertype_info[0]
        if ethertype == 0x8100:  # VLAN
            # skip VLAN shim
            start_offset += 4
            ethertype = ethertype[2]

        # if we see this, maybe skip the offending ethertype?
        assert ethertype == 0x0800, f"Unknown ethertype {hex(ethertype)}"  # IP

        # IP header
        v = data[start_offset]
        version = v >> 4
        ihl = v & 0x0F

        if version == 4:
            protocol = data[start_offset + 9]

            assert ihl >= 5, f"Bad ihl for ipv4 packet: {ihl}"
            start_offset += 4 * ihl

            assert protocol == 17, f"Unrecognized protocol: {protocol}"  # UDP

            # UDP header
            start_offset += 8

        else:
            raise Exception(f"FIXME: can't handle IP version {version}")

        # VXLAN header
        start_offset += 8

        packet = data[start_offset:]
        self.send_raw(packet)

    def run(self):
        self.capture.loop(0, self.handle_packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Try to strip VXLAN headers and send packets to veth interface pair"
    )
    parser.add_argument(
        "-d",
        "--destroy-on-exit",
        dest="destroy_on_exit",
        action="store_true",
        help="destroy veth pair on exit, default is only destroy if it didn't exist",
    )
    parser.add_argument(
        "-D",
        "--no-destroy-on-exit",
        dest="destroy_on_exit",
        action="store_false",
        help="keep veth pair on exit",
    )
    parser.add_argument(
        "-i",
        "--capture-interface",
        dest="capture_interface",
        required=True,
        help="Interface or pcap file to capture VXLAN packets from",
        type=str,
    )
    parser.add_argument(
        "-v",
        "--veth-base-name",
        dest="veth_base",
        help="create <veth_base>_in and <veth_base>_out as pair, default is veth_test",
        default="veth_test",
    )
    parser.add_argument(
        "-f",
        "--filter",
        dest="filter",
        help="pcap filter to match desired vxlan traffic",
        default="(udp dst port 4789) or (vlan and udp dst port 4789)",
    )

    parser.set_defaults(destroy_on_exit=None)

    args = parser.parse_args()

    x = VxlanDecap(
        args.veth_base,
        args.capture_interface,
        destroy_on_exit=args.destroy_on_exit,
        filter=args.filter,
    )

    x.run()
