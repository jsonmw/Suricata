-- Jason Wild
-- CISS 469
-- Signature-based detection Script

-- Global variables

threshold = 3  -- highest allowed entropy
percent = 0.85 -- % of possible entropy

-- Initiates script and specifies the payload field is needed

function init (args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

-- Calculates the Shannon Entropy for the given domain string

local function calcEntropy(domain)
    local counts = {}

    for i = 1, #domain do
        local byte = string.byte(domain, i)
        counts[byte] = (counts[byte] or 0) + 1
    end

    local entropy = 0
    for _, count in pairs(counts) do
        local probability = count / #domain
        entropy = entropy - probability * (math.log(probability) / math.log(2))
    end

    return entropy
end

-- Returns 1 if threshold and percentage of max specified by globals are met

local function processDomain(domain)
    local entropy = calcEntropy(domain:gsub("%.", ""))
    local max = math.log(#domain) / math.log(2) -- Maximum entropy for string length

    local result = 0
    if ((entropy >= threshold) and (entropy >= (0.85 * max))) then
        result = 1
    end
    return result
end

-- Extracts the domain from the DNS payload and processes it.

function match(args)
    local raw = tostring(args["payload"])
    local domain = tostring(raw:gsub("[^%w%%-]", ""))

    -- check for null, and process
    if domain and domain ~= "" then
        local result = processDomain(domain)
        return result
    else
        return 0
    end
end

return 0