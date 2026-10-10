-- MODULE: firewall_engine
-- Unified network domain abstraction and dynamic packet evaluation logic.

local firewall_engine = {}

-- 1. Abstraction & Data Types: Prototype-based Packet Object

local Packet = {}
Packet.__index = Packet

function Packet.new(source_ip, destination_port, protocol, payload_bytes)
    local instance = {
        source_ip        = source_ip,
        destination_port = tonumber(destination_port),
        protocol         = string.upper(protocol or "TCP"),
        payload_bytes    = tonumber(payload_bytes or 0)
    }
    setmetatable(instance, Packet)
    return instance
end

-- Distinctive Feature Metamethod: String conversion
function Packet:__tostring()
    return string.format("[%s] %s:%d (Length: %d bytes)", 
        self.protocol, self.source_ip, self.destination_port, self.payload_bytes)
end

firewall_engine.Packet = Packet

-- 2. Orthogonality & Closure Abstraction: The Rule Engine

function firewall_engine.create_engine()
    -- Encapsulated private state (Support for Abstraction)
    local drop_counter = 0
    local accept_counter = 0
    local dynamic_rules = {}

    local engine = {}

    -- Orthogonality: Rules are first-class functions added directly to table
    function engine.add_rule(description, rule_fn)
        table.insert(dynamic_rules, { desc = description, evaluate = rule_fn })
    end

    -- Expressivity: Multiple return values (Decision, Reason)
    function engine.evaluate_packet(packet)
        for _, rule in ipairs(dynamic_rules) do
            local matched = rule.evaluate(packet)
            if matched then
                drop_counter = drop_counter + 1
                return "DROP", rule.desc
            end
        end
        accept_counter = accept_counter + 1
        return "ACCEPT", "Passed all security filters"
    end

    function engine.get_statistics()
        return {
            accepted = accept_counter,
            dropped  = drop_counter,
            total    = accept_counter + drop_counter
        }
    end

    return engine
end

-- 3. Exception Handling: Protected Parsing of Ingress Network Telemetry

function firewall_engine.safe_parse_log(raw_line)
    -- Functional protected call (pcall) to catch malformed lines safely
    local success, result_or_err = pcall(function()
        if not raw_line or raw_line == "" then
            error("Empty telemetry line encountered")
        end

        local ip, port, proto, bytes = raw_line:match("([%d%.]+),([%d]+),([%a]+),([%d]+)")
        if not ip or not port then
            error("Corrupted frame syntax: " .. raw_line)
        end

        return Packet.new(ip, port, proto, bytes)
    end)

    if success then
        return result_or_err, nil
    else
        return nil, result_or_err
    end
end

return firewall_engine