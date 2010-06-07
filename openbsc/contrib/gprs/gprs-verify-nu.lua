-- This script verifies that the N(U) is increasing...
--
do
	local nu_state_src = {}

	local function init_listener()
		-- handle the port as NS over IP
		local udp_port_table = DissectorTable.get("udp.port")
		local gprs_ns_dis = Dissector.get("gprs_ns")
		udp_port_table:add(23000,gprs_ns_dis)

		-- we want to look here...
		local llc_sapi_get = Field.new("llcgprs.sapib")
		local llc_nu_get = Field.new("llcgprs.nu")
		local bssgp_tlli_get = Field.new("bssgp.tlli")

		local tap = Listener.new("ip", "udp.port == 23000")
		function tap.packet(pinfo,tvb,ip)
			local llc_sapi = llc_sapi_get()
			local llc_nu = llc_nu_get()
			local bssgp_tlli = bssgp_tlli_get()

			if not llc_sapi or not llc_nu or not bssgp_tlli then
				return
			end

			local ip_src = tostring(ip.ip_src)
			local bssgp_tlli = tostring(bssgp_tlli)
			local llc_nu = tostring(llc_nu)
			local llc_sapi = tostring(llc_sapi)

			local src_key = ip_src .. "-" .. bssgp_tlli .. "-" .. llc_sapi
			local last_nu = nu_state_src[src_key]
			if not last_nu then
				-- print("Establishing mapping for " .. src_key)
				nu_state_src[src_key] = llc_nu
				return
			end

			local function tohex(number)
				return string.format("0x%x", tonumber(number))
			end

			nu_state_src[src_key] = llc_nu
			if tonumber(last_nu) + 1 ~= tonumber(llc_nu) then
				print("JUMP in N(U) on TLLI " .. tohex(bssgp_tlli) .. " and SAPI: " .. llc_sapi .. " src: " .. ip_src)
				print("\t last: " .. last_nu .. " now: " .. llc_nu)
			end
		end

		function tap.draw()
		end

		function tap.reset()
		end
	end
	init_listener()
end

