-- MAIN RUNNER: Network Access Control and Rule Evaluation Engine

local engine_mod = require("firewall_engine")

print("====================================================================")
print("     COMP2007: Lua Traffic Evaluation Engine Benchmark              ")
print("====================================================================")

-- Initialize firewall engine instance
local firewall = engine_mod.create_engine()

-- Register dynamic rule closures (First-Class Functions)
firewall.add_rule("Drop Telnet Insecure Port (23)", function(pkt)
    return pkt.destination_port == 23
end)

firewall.add_rule("Block Blacklisted Subnet (10.66.*)", function(pkt)
    return pkt.source_ip:find("^10%.66%.") ~= nil
end)

firewall.add_rule("Prevent Oversized UDP Datagrams (> 1500 bytes)", function(pkt)
    return pkt.protocol == "UDP" and pkt.payload_bytes > 1500
end)

-- Mock Ingress Network Telemetry Stream
local network_stream = {
    "192.168.1.10,80,TCP,512",
    "10.66.4.12,443,TCP,1024",       -- Subnet match (DROP)
    "172.16.0.5,23,TCP,64",           -- Telnet port match (DROP)
    "CORRUPTED_INGRESS_HEADER_DATA",  -- Malformed input (Protected call error)
    "192.168.1.15,53,UDP,2048",       -- Oversized UDP match (DROP)
    "127.0.0.1,443,TCP,256"           -- Clean packet (ACCEPT)
}

print("\n*** Processing Inbound Network Telemetry Stream ***")

for index, raw_entry in ipairs(network_stream) do
    -- Safe parse using multiple return values and pcall
    local packet, err = engine_mod.safe_parse_log(raw_entry)

    if err then
        print(string.format("[LOG WARNING] Record %d Rejected: %s", index, err))
    else
        -- Evaluate packet against active rules
        local action, reason = firewall.evaluate_packet(packet)
        print(string.format("[TRAFFIC %s] %s -> %s", action, tostring(packet), reason))
    end
end

-- Display Engine Aggregated Statistics
local stats = firewall.get_statistics()
print("\n*** Firewall Engine Operational Summary ***")
print(string.format("Total Frames Processed : %d", stats.total))
print(string.format("Frames Accepted        : %d", stats.accepted))
print(string.format("Frames Dropped         : %d", stats.dropped))
