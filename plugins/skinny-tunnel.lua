--
--   Skinny IPv6-in-IPv6 Extension Header
--   https://www.ietf.org/id/draft-smith-skinny-ipv6-in-ipv6-tunnelling-00.txt
--
--   0                   1                   2                   3
--   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--  |  Next Header  |  Hdr Ext Len  |     Type      |     Length    |
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--  |    Reserved   |      Inner Payload Length     |Inner Hop Limit|
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--  |                                                               |
--  +                     Inner SA 64 bit Prefix                    +
--  |                                                               |
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--  |                                                               |
--  +                     Inner DA 64 bit Prefix                    +
--  |                                                               |
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--  |                                                               |
--  +                      Inner DA 64 bit IID                      +
--  |                                                               |
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- 

local skinny_proto = Proto("skinny_protocol", "IPv6 over IPv6 Skinny Tunneling Protocol")
local f = skinny_proto.fields
local ipv6_opt_type = Field.new("ipv6.opt.experimental")

f.reserved              = ProtoField.new("Reserved", "skinny.reserved", ftypes.UINT8, nil, base.DEC)
f.inner_payload_length  = ProtoField.new("Inner Payload Length", "skinny.inner_payload_length", ftypes.UINT16, nil, base.DEC)
f.inner_hop_limit       = ProtoField.new("Inner Hop Limit", "skinny.inner_hop_limit", ftypes.UINT8, nil, base.DEC)
f.inner_src_addr        = ProtoField.new("Inner SA 64 bit Prefix", "skinny.inner_src_addr", ftypes.UINT64, nil, base.HEX)
f.inner_dst_addr        = ProtoField.new("Inner DA 64 bit Prefix", "skinny.inner_dst_addr", ftypes.UINT64, nil, base.HEX)


function skinny_proto.dissector(buffer, pinfo, tree)
	if ipv6_opt_type then
		local subtree = tree:add(skinny_proto, buffer(58, 20))
		subtree:add(f.reserved, buffer(58, 1))
		subtree:add(f.inner_payload_length, buffer(59, 2))
		subtree:add(f.inner_hop_limit, buffer(61, 1))
		subtree:add(f.inner_src_addr, buffer(62, 8))
		subtree:add(f.inner_dst_addr, buffer(70, 8))
	end
end

register_postdissector(skinny_proto)
