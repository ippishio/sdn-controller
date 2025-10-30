import logging
import binascii
import socket
import functools
import random
import multiprocessing as mp
from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
    HANDSHAKE_DISPATCHER,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.dpid import dpid_to_str
from os_ken.lib.packet import ethernet, arp, ipv4
from os_ken.lib.packet.packet_utils import struct
from os_ken.lib import hub
from os_ken import utils
from ipaddress import IPv4Address

from controller.db.models import BalanceRule, BalanceAlgroithm, Protocol
from controller.api.app import run_api


class Controller(OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        self.cur_gid = 1  # некая гарантия уникальности group_id
        self.datapath_mac_table = {}  # изученные mac
        self.switches = {}  # dpid -> datapath
        self.virtual_ip_map = {}  # vip - gid, mac
        self.backend_mapping = {  # вообще, можно было посылать ARP запросы всей подсети, но это вроде выходит за рамки задания
            "10.0.0.1": {
                "sw_dpid": "0000000000000001",
                "port": 1,
                "mac": "00:00:00:00:00:01",
            },
            "10.0.0.2": {
                "sw_dpid": "0000000000000001",
                "port": 2,
                "mac": "00:00:00:00:00:02",
            },
            "10.0.0.3": {
                "sw_dpid": "0000000000000002",
                "port": 1,
                "mac": "00:00:00:00:00:03",
            },
            "10.0.0.4": {
                "sw_dpid": "0000000000000002",
                "port": 2,
                "mac": "00:00:00:00:00:04",
            },
        }
        # постыдно писать mac-и руками учитывая, что ниже код для L2 Learning, но боюсь
        # смешивать это, чтобы ничего не сломалось
        super(Controller, self).__init__(*args, **kwargs)
        for handler in logging.getLogger().handlers:
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
                    datefmt="%H:%M:%S",
                )
            )
            handler.setLevel(logging.DEBUG)
        self.start_api_endpoint()

    def start_api_endpoint(self):
        # запускаем в отдельном процессе FastAPI
        # чтобы не конфликтовали потоки
        self.logger.info("Started API endpoint")
        self.req_pipe_in, self.req_pipe_out = mp.Pipe()
        self.resp_pipe_in, self.resp_pipe_out = mp.Pipe()
        p = mp.Process(target=run_api, args=(self.req_pipe_in, self.resp_pipe_out))
        p.start()
        hub.spawn(self._api_listener)

    def _api_listener(self):
        # самопальный RPC
        pipe_in = self.req_pipe_out
        while True:
            req = pipe_in.recv()
            if req:
                self.logger.debug(f"new requet {str(req)}")
                method = getattr(self, req["method"])
                method(*req["args"], **req["kwargs"])
                req = None

    def _send_exception(func):

        @functools.wraps(func)
        def handler(self, *args, **kwargs):
            try:
                func(self, *args, **kwargs)
            except Exception as e:
                self.resp_pipe_in.send({"rc": 1, "details": str(e)})
                self.logger.exception(
                    f"Captured method '{getattr(func, '__name__', 'Unknown')}' error"
                )
            else:
                self.resp_pipe_in.send({"rc": 0, "details": "OK"})

        return handler

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def error_msg_handler(self, ev):
        # отлов ошибок
        error = ev.msg.datapath.ofproto.ofp_error_to_jsondict(ev.msg.type, ev.msg.code)
        self.logger.error(
            "openflow error received:\n\t\ttype={}\n\t\tcode={}\n\t\tdata={}".format(
                error.get("type"), error.get("code"), ev.msg.data
            )
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        # хендшейки, запоминание свитчей, установка нулевого flow
        datapath = ev.msg.datapath
        dpid = dpid_to_str(datapath.id)
        self.datapath_mac_table[dpid] = {}
        self.switches[dpid] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.logger.info(
            "Handshake taken place with {}".format(dpid_to_str(datapath.id))
        )
        self.add_flow(datapath, 0, match, actions, idle=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        #  обработка входящих пакетов на контроллер
        msg = ev.msg
        in_port = msg.match["in_port"]
        eth_header = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        datapath = msg.datapath
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        self.logger.debug(
            "❗️event 'packet in' from datapath: {}".format(dpid_to_str(datapath.id))
        )
        self.logger.debug(f"mac mapping: {self.datapath_mac_table}")
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is not None:
            self.logger.debug(f"IPv4 packet source: {ipv4_pkt.src}, destination: {ipv4_pkt.dst}")
            if ipv4_pkt.src == "10.0.0.1":
                self.logger.debug(f"!!packet message from 10.0.0.1: {ev.msg}")
                self.logger.debug(f"!!packet message match 10.0.0.1: {ev.msg.match}")
        arp_pkt = pkt.get_protocol(arp.arp)
        #  ответ ARP запрос для VIP
        if arp_pkt is not None:
            if (
                arp_pkt.opcode == arp.ARP_REQUEST
                and arp_pkt.dst_ip in self.virtual_ip_map.keys()
            ):
                vip = arp_pkt.dst_ip
                vmac = self.virtual_ip_map[vip]["mac"]
                self.logger.debug(f"found ARP request to VIP {vip}")
                self._send_arp_reply(datapath, in_port, arp_pkt, vip, vmac)
        # собственно mac-learning
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]  # default
        if eth_header is not None:
            self.logger.debug(f"Ethernet header source: {eth_header.src}, destination: {eth_header.dst}")
            self.datapath_mac_table[dpid_to_str(datapath.id)][eth_header.src] = in_port
            if eth_header.dst in self.datapath_mac_table[dpid_to_str(datapath.id)].keys():
                # обработать
                out_port = self.datapath_mac_table[dpid_to_str(datapath.id)][eth_header.dst]
                self.add_flow(
                    datapath,
                    1,
                    match=parser.OFPMatch(eth_dst=eth_header.dst),
                    actions=[parser.OFPActionOutput(port=out_port)],
                )
                self.logger.debug(
                    f"new flow: mac {eth_header.dst} to port {out_port} on dpid {dpid_to_str(datapath.id)}"
                )
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        self.logger.info("Sending packet out")
        datapath.send_msg(out)
        return

    def _send_arp_reply(self, datapath, in_port, arp_request, reply_ip, reply_mac):
        parser = datapath.ofproto_parser

        arp_reply = arp.arp(
            hwtype=arp_request.hwtype,
            proto=arp_request.proto,
            hlen=arp_request.hlen,
            plen=arp_request.plen,
            opcode=arp.ARP_REPLY,
            src_mac=reply_mac,
            src_ip=reply_ip,
            dst_mac=arp_request.src_mac,
            dst_ip=arp_request.src_ip,
        )

        eth = ethernet.ethernet(
            dst=arp_request.src_mac,
            src=reply_mac,
            ethertype=ethernet.ether.ETH_TYPE_ARP,
        )

        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_reply)
        pkt.serialize()

        actions = [parser.OFPActionOutput(port=in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data,
        )

        datapath.send_msg(out)
        self.logger.info(
            "ARP Reply sent for %s -> %s", arp_request.dst_ip, arp_request.src_ip
        )

    def __get_next_gid(self):
        self.cur_gid += 1
        return self.cur_gid

    def add_flow(self, datapath, priority, match, actions, table=0, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            table_id=table,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
        )
        self.logger.info("Flow-Mod written to {}".format(dpid_to_str(datapath.id)))
        datapath.send_msg(mod)

    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        self.logger.info("Flow-Mod deleted from {}".format(dpid_to_str(datapath.id)))
        datapath.send_msg(mod)

    def add_balancing_group(
        self, datapath, backends, algorithm: BalanceAlgroithm, group_id
    ):
        # создание группы
        buckets = []
        parser = datapath.ofproto_parser
        ofp = parser.ofproto

        for backend in backends:
            buckets.append(
                parser.OFPBucket(
                    weight=1,
                    actions=[
                        parser.OFPActionSetField(ipv4_dst=backend["ip"]),
                        parser.OFPActionSetField(eth_dst=backend["mac"]),
                        parser.OFPActionOutput(port=backend["port"]),
                    ],
                )
            )
        group_mod_req = parser.OFPGroupMod(
            datapath=datapath,
            command=ofp.OFPGC_ADD,
            type_=ofp.OFPGT_SELECT,
            group_id=group_id,
            buckets=buckets,
        )
        datapath.send_msg(group_mod_req)
        self.logger.info(f"added group {group_id} to dpid {dpid_to_str(datapath.id)}")
        # self.nicira_add_algorithm_to_group(datapath, group_id, algorithm)
        # всё, что связано с nicira - страшный сон

    def delete_group(self, datapath, group_id):
        parser = datapath.ofproto_parser
        ofp = parser.ofproto
        group_mod_req = parser.OFPGroupMod(
            datapath=datapath,
            command=ofp.OFPGC_DELETE,
            group_id=group_id,
            type_=0,
        )
        datapath.send_msg(group_mod_req)
        self.logger.info(
            f"deleted group {group_id} from dpid {dpid_to_str(datapath.id)}"
        )

    def add_vip_to_group_flow(
        self, datapath, vip: IPv4Address, protocol: Protocol, group_id
    ):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=str(vip),
            ip_proto=protocol if protocol != Protocol.ip else None,
            ct_state=(0x00, 0x20),  # -trk
            ct_zone=0,
        )
        actions = [
            parser.NXActionCT(
                flags=0x01,  # NX_CT_F_COMMIT
                zone_src=None,
                zone_ofs_nbits=0,
                recirc_table=0,
                alg=0,
                actions=[],
            ),
        ]
        self.add_flow(datapath, priority=2, match=match, actions=actions)

        self.logger.info(
            f"added group flow with id {group_id} to dpid {dpid_to_str(datapath.id)} with VIP {str(vip)}"
        )
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=str(vip),
            ip_proto=protocol if protocol != Protocol.ip else None,
            ct_state=(0x20, 0x20),  # +trk
            ct_zone=0,
        )
        actions = [
            parser.OFPActionGroup(group_id=group_id),
        ]
        self.add_flow(datapath, priority=2, match=match, actions=actions)

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src="10.0.0.1",
            ip_proto=protocol if protocol != Protocol.ip else None,
        )
        ofproto = parser.ofproto
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, priority=20, match=match, actions=actions)
        self.logger.info(
            f"added conntrack intercept group flow with id {group_id} to dpid {dpid_to_str(datapath.id)} with VIP {str(vip)}"
        )
        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=protocol if protocol != Protocol.ip else None,
            ct_state=(0x02 | 0x08, 0x02 | 0x08),  # +est+rpl
        )
        actions = [
            parser.NXActionCT(
                flags=0x01,
                zone_src=None,
                zone_ofs_nbits=0,
                alg=0,
                recirc_table=0,
                actions=[
                    parser.NXActionNAT(
                        flags=0x01,
                        range_ipv4_min=str(vip),
                        range_ipv4_max=str(vip),
                    )
                ],
            ),
        ]
        self.add_flow(datapath, priority=3, match=match, actions=actions)
        self.logger.info(
            f"added vip return flow from host to dpid {dpid_to_str(datapath.id)}"
        )

    @_send_exception
    def apply_balancing_rule(self, rule: BalanceRule):
        # парсим объект правила и делаем все необходимое
        for ip in rule.backend_ip:
            if str(ip) not in self.backend_mapping.keys():
                raise ValueError(f"Backend IP {str(ip)} not in the network")
        if rule.virtual_ip in self.backend_mapping.keys():
            raise ValueError(f"Can't assign Virtual IP {str(ip)}: host already exists")
        if rule.port is not None and (rule.port < 0 or rule.port > 65535):
            raise ValueError(f"Incorrect port {rule.port}")
        hosts_grouped_by_switches = {}
        gid = self.__get_next_gid()
        if str(rule.virtual_ip) not in self.virtual_ip_map.keys():
            vip_mapping = {
                "mac": Controller._generate_mac(),
                "gid": gid,
            }
        else:
            raise ValueError(f"Virtual IP {rule.virtual_ip} already aquired")
        for ip in rule.backend_ip:
            dpid = self.backend_mapping[str(ip)]["sw_dpid"]
            sw_port = self.backend_mapping[str(ip)]["port"]
            mac = self.backend_mapping[str(ip)]["mac"]
            if dpid not in hosts_grouped_by_switches:
                hosts_grouped_by_switches[dpid] = []
            hosts_grouped_by_switches[dpid].append(
                {"ip": str(ip), "port": sw_port, "mac": mac}
            )
        for dpid in hosts_grouped_by_switches.keys():
            datapath = self.switches[dpid]
            hosts = hosts_grouped_by_switches[dpid]
            self.add_balancing_group(datapath, hosts, rule.algorithm, gid)
            self.add_vip_to_group_flow(datapath, rule.virtual_ip, rule.protocol, gid)
        self.virtual_ip_map[str(rule.virtual_ip)] = vip_mapping
        self.logger.debug("added FUCKIng rule hope it is FUCKING works")

    @_send_exception
    def delete_balancing_rule(self, rule: BalanceRule):
        hosts_grouped_by_switches = {}
        for ip in rule.backend_ip:
            dpid = self.backend_mapping[str(ip)]["sw_dpid"]
            sw_port = self.backend_mapping[str(ip)]["port"]
            mac = self.backend_mapping[str(ip)]["mac"]
            if dpid not in hosts_grouped_by_switches:
                hosts_grouped_by_switches[dpid] = []
            hosts_grouped_by_switches[dpid].append(
                {"ip": ip, "port": sw_port, "mac": mac}
            )
        for dpid in hosts_grouped_by_switches.keys():
            datapath = self.switches[dpid]
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=str(rule.virtual_ip),
                ip_proto=rule.protocol if rule.protocol != Protocol.ip else None,
            )
            self.delete_flow(datapath, match)
            hosts = hosts_grouped_by_switches[dpid]
            for h in hosts:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=rule.protocol if rule.protocol != Protocol.ip else None,
                    ipv4_src=h["ip"],
                    ipv4_dst=str(rule.virtual_ip),
                )
                self.delete_flow(datapath, match)
            gid = self.virtual_ip_map[str(rule.virtual_ip)]["gid"]
            self.delete_group(datapath, gid)
        self.virtual_ip_map.pop(str(rule.virtual_ip))
        self.logger.debug("deleted rule flows and groups")

    @staticmethod
    def _generate_mac():
        mac_parts = []
        for _ in range(6):
            hex_octet = f"{random.randint(0, 255):02x}"
            mac_parts.append(hex_octet)
        return ":".join(mac_parts)

    @staticmethod
    def ip_to_int(ip_str):
        """Convert IP string to integer"""
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    @staticmethod
    def mac_to_int(mac_str):
        """
        Convert MAC address string to integer
        Example: "00:00:00:00:00:01" -> 1
        """
        # Remove any separators
        mac_clean = mac_str.replace(":", "").replace("-", "")

        # Convert to integer (base 16)
        return int(mac_clean, 16)
