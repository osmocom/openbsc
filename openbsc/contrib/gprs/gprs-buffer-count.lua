-- I count the buffer space needed for LLC PDUs in the worse case and print it

do
	local function init_listener()
		-- handle the port as NS over IP
		local udp_port_table = DissectorTable.get("udp.port")
		local gprs_ns_dis = Dissector.get("gprs_ns")
		udp_port_table:add(23000,gprs_ns_dis)

		-- bssgp filters
		local bssgp_pdu_get = Field.new("bssgp.pdu_type")
		local bssgp_delay_get = Field.new("bssgp.delay_val")
		local llcgprs_get = Field.new("llcgprs")
		local pdus = nil

		print("START...")

		local tap = Listener.new("ip", "udp.port == 23000 && bssgp.pdu_type == 0")
		function tap.packet(pinfo,tvb,ip)
			local pdu = bssgp_pdu_get()
			local len = llcgprs_get().len
			local delay = bssgp_delay_get()

			-- only handle bssgp, but we also want the IP frame
			if not pdu then
				return
			end

			if tonumber(tostring(delay)) == 65535 then
				pdus = { next = pdus,
					 len = len,
					 expires = -1 }
			else
				local off = tonumber(tostring(delay)) / 100.0
				pdus = { next = pdus,
					 len = len,
					 expires = pinfo.rel_ts + off }
			end
			local now_time = tonumber(tostring(pinfo.rel_ts))
			local now_size = 0
			local l = pdus
			local prev = nil
			local count = 0
			while l do
				if now_time < l.expires or l.expires == -1 then
					now_size = now_size + l.len
					prev = l
					l = l.next
					count = count + 1
				else
					-- delete things
					if prev == nil then
						pdus = nil
						l = nil
					else
						prev.next = l.next
						l = l.next
					end
				end
			end
--			print("TOTAL: " .. now_time .. " PDU_SIZE: " .. now_size)
			print(now_time .. " " .. now_size / 1024.0 .. " " .. count)
--			print("NOW: " .. tostring(pinfo.rel_ts) .. " Delay: " .. tostring(delay) .. " Length: " .. tostring(len))
		end

		function tap.draw()
			-- well... this will not be called...
--			for ip,bssgp_histo in pairs(dumpers) do
--				print("IP " .. ip)
--			end
			print("END")
		end

		function tap.reset()
			-- well... this will not be called...
		end
	end

	init_listener()
end
