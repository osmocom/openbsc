print("Ni hao")


do
	local tap = Listener.new("ip", "rtp")
	local rtp_ssrc = Field.new("rtp.ssrc")
	local frame_time = Field.new("frame.time_relative")
	local rtp = Field.new("rtp")

	function tap.packet(pinfo, tvb, ip)
		local ip_src, ip_dst = tostring(ip.ip_src), tostring(ip.ip_dst)
		local rtp_data = rtp()
		local filename = "rtp_ssrc" .. rtp_ssrc() "_src_" .. ip_src .. "_to_" .. ip_dst .. ".state"
		local f = io.open(filename, "a")

		f:write(tostring(frame_time()) .. " ")
		f:write(tostring(rtp_data.value))
		f:write("\n")
		f:close()
	end

	function tap.draw()
		print("DRAW")
	end
	function tap.reset()
		print("RESET")
	end
end
