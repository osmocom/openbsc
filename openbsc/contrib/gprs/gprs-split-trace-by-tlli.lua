-- Create a file named by_ip/''ip_addess''.cap with all ip traffic of each ip host. (works for tshark only)
-- Dump files are created for both source and destination hosts
do
	local dir = "by_tlli"
	local dumpers = {}
	local function init_listener()
		local udp_port_table = DissectorTable.get("udp.port")
		local gprs_ns_dis = Dissector.get("gprs_ns")
		udp_port_table:add(23000,gprs_ns_dis)

		local field_tlli = Field.new("bssgp.tlli")
		local tap = Listener.new("ip", "udp.port == 23000")

		-- we will be called once for every IP Header.
		-- If there's more than one IP header in a given packet we'll dump the packet once per every header
		function tap.packet(pinfo,tvb,ip)
			local tlli = field_tlli()
			if not tlli then
				return
			end

			local tlli_str = tostring(tlli)
			tlli_dmp = dumpers[tlli_str]
			if not tlli_dmp then
				local tlli_hex = string.format("0x%x", tonumber(tlli_str))
				print("Creating dump for TLLI " .. tlli_hex)
				tlli_dmp = Dumper.new_for_current(dir .. "/" .. tlli_hex .. ".pcap")
				dumpers[tlli_str] = tlli_dmp
			end
			tlli_dmp:dump_current()
			tlli_dmp:flush()
		end
		function tap.draw()
			for tlli,dumper in pairs(dumpers) do
				 dumper:flush()
			end
		end
		function tap.reset()
			for tlli,dumper in pairs(dumpers) do
				 dumper:close()
			end
			dumpers = {}
		end
	end
	init_listener()
end
