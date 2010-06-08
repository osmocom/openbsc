-- Simple LUA script to print the size of BSSGP messages over their type...

do
	local ip_bucket = {}

	local pdu_types = {}
	pdu_types[ 6] = "PAGING"
	pdu_types[11] = "SUSPEND"
	pdu_types[12] = "SUSPEND-ACK"
	pdu_types[32] = "BVC-BLOCK"
	pdu_types[33] = "BVC-BLOCK-ACK"
	pdu_types[34] = "BVC-RESET"
	pdu_types[35] = "BVC-RESET-ACK"
	pdu_types[36] = "UNBLOCK"
	pdu_types[37] = "UNBLOCK-ACK"
	pdu_types[38] = "FLOW-CONTROL-BVC"
	pdu_types[39] = "FLOW-CONTROL-BVC-ACK"
	pdu_types[40] = "FLOW-CONTROL-MS"
	pdu_types[41] = "FLOW-CONTROL-MS-ACK"
	pdu_types[44] = "LLC-DISCARDED"

	local function init_listener()
		-- handle the port as NS over IP
		local udp_port_table = DissectorTable.get("udp.port")
		local gprs_ns_dis = Dissector.get("gprs_ns")
		udp_port_table:add(23000,gprs_ns_dis)

		-- bssgp filters
		local bssgp_pdu_get = Field.new("bssgp.pdu_type")
		local udp_length_get = Field.new("udp.length")

		local tap = Listener.new("ip", "udp.port == 23000")
		function tap.packet(pinfo,tvb,ip)
			local pdu = bssgp_pdu_get()
			local len = udp_length_get()

			-- only handle bssgp, but we also want the IP frame
			if not pdu then
				return
			end

			pdu = tostring(pdu)
			if tonumber(pdu) == 0 or tonumber(pdu) == 1 then
				return
			end

			local ip_src = tostring(ip.ip_src)
			local bssgp_histo = ip_bucket[ip_src]
			if not bssgp_histo then
				bssgp_histo = {}
				ip_bucket[ip_src] = bssgp_histo
			end

			local key = pdu
			local bucket = bssgp_histo[key]
			if not bucket then
				bucket = {}
				bssgp_histo[key] = bucket
			end

			table.insert(bucket, tostring(len))
			print("IP: " .. ip_src .. " PDU: " .. pdu_types[tonumber(pdu)] .. " Length: " .. tostring(len))
		end

		function tap.draw()
			-- well... this will not be called...
--			for ip,bssgp_histo in pairs(dumpers) do
--				print("IP " .. ip)
--			end
		end

		function tap.reset()
			-- well... this will not be called...
		end
	end

	init_listener()
end
