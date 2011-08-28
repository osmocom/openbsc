-- I count the buffer space needed for LLC PDUs in the worse case and print it

do
	local function init_listener()
		-- handle the port as NS over IP
		local udp_port_table = DissectorTable.get("udp.port")
		local gprs_ns_dis = Dissector.get("gprs_ns")
		udp_port_table:add(23000,gprs_ns_dis)

		-- bssgp filters
		local bssgp_pdu_get = Field.new("bssgp.pdu_type")
		local udp_get = Field.new("ip.len")
		local racap_get = Field.new("gsm_a_gm.elem_id")
		local packets = 0
		local org_bytes = 0

		local tap = Listener.new("ip", "udp.port == 23000")
		function tap.packet(pinfo,tvb,ip)
			local pdu = bssgp_pdu_get()
			local racap = racap_get()
			org_bytes = org_bytes + tonumber(tostring(udp_get()))
			packets = packets + 1
		end

		function tap.draw()
			-- well... this will not be called...
--			for ip,bssgp_histo in pairs(dumpers) do
--				print("IP " .. ip)
--			end
			print("Packets: " .. packets ..
			     " bytes: " .. org_bytes / 1024.0 ..
			     " cap: " .. (org_bytes - (2580*18)) / 1024.0)
			print("END")
		end

		function tap.reset()
			-- well... this will not be called...
		end
	end

	init_listener()
end
