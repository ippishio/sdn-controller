def add_vip_to_group_flow(
    self, datapath, vip: IPv4Address, protocol: Protocol, group_id
):
    #  conntrack остался сильнее меня...
    #  я оставил в коментариях свои попытки применить его
    #  но в итоговой реализации при возврате пакета src_ip не меняется на vip
    parser = datapath.ofproto_parser
    match = parser.OFPMatch(
        eth_type=0x0800,
        ipv4_dst=str(vip),
        ip_proto=protocol if protocol != Protocol.ip else None,
        ct_state=(0x00, 0x01),
        ct_zone=0,
    )
    actions = [
        parser.NXActionCT(
            flags=0x01,  # NX_CT_F_COMMIT
            zone_src=0,
            zone_ofs_nbits=0,
            recirc_table=0,
            alg=0,
            actions=[parser.OFPActionGroup(group_id=group_id)],
        ),
        parser.OFPActionGroup(group_id=group_id),
    ]
    self.add_flow(datapath, priority=2, match=match, actions=actions)
    self.logger.info(
        f"added group flow with id {group_id} to dpid {dpid_to_str(datapath.id)} with VIP {str(vip)}"
    )
    match = parser.OFPMatch(
        eth_type=0x0800,
        ip_proto=protocol if protocol != Protocol.ip else None,
        # ct_state = 0x06  # +est+rpl
        ipv4_dst=str(vip),
    )
    actions = [
        parser.NXActionCT(
            flags=0x01,
            zone_src=None,
            zone_ofs_nbits=0,
            recirc_table=0,
            alg=0,
            actions=[
                parser.NXActionNAT(
                    flags=0x01,
                    range_ipv4_min=str(vip),
                    range_ipv4_max=str(vip),
                )
            ],
        ),
        parser.OFPActionSetField(ipv4_src=str(vip)),
    ]
    # self.add_flow(datapath, priority=3, match=match, actions=actions)
    self.logger.info(
        f"added vip return flow from host to dpid {dpid_to_str(datapath.id)}"
    )
