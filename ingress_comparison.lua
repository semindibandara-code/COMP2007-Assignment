-- Execution with explicit branching
local function parse_ingress_frame(raw_str)
    if not raw_str or raw_str == "" then
        return nil, "FrameError: Empty ingress payload"
    end
    local ip, port, proto = raw_str:match("([^,]+),([^,]+),([^,]+)")
    if not ip or not port then
        return nil, "FrameError: Incomplete frame delimiters"
    end
    return { ip = ip, port = tonumber(port), proto = proto }, nil
end

local frame, err = parse_ingress_frame("10.0.0.1,80,TCP")
if not frame or err then
    print("Ingress dropped: " .. tostring(err))
else
    print("Processing payload directed to port: " .. frame.port)
end

