-- JA3 TLS fingerprint via ngx.ssl.clienthello APIs (OpenResty 1.19.3.2+).
-- raw_client_hello() is not available; use structured APIs instead.
-- Call _M.compute(ssl_clt) from ssl_client_hello_by_lua* context only.

local _M = {}

local function u16(s, i)
    local a, b = string.byte(s, i, i + 1)
    if not a or not b then return nil end
    return a * 256 + b
end

local function is_grease(v)
    local hi = math.floor(v / 256)
    local lo = v % 256
    return hi == lo and lo % 16 == 10
end

-- ssl_clt: result of require("ngx.ssl.clienthello")
function _M.compute(ssl_clt)
    -- client_version is 0x0303 (771) for all TLS 1.2/1.3 ClientHellos (RFC 8446).
    -- nginx only accepts TLSv1.2+, so this is always correct.
    local tls_ver = 771

    -- Cipher suites: GREASE already excluded by the API
    local ciphers = ssl_clt.get_client_hello_ciphers() or {}

    -- Extension type list: GREASE already excluded by the API
    local exts = ssl_clt.get_client_hello_ext_present() or {}

    -- supported_groups (ext 10): 2-byte list-length + 2-byte group IDs
    local curves = {}
    local gdata  = ssl_clt.get_client_hello_ext(10)
    if gdata and #gdata >= 2 then
        local glen = u16(gdata, 1)
        if glen then
            for i = 0, glen / 2 - 1 do
                local c = u16(gdata, 3 + i * 2)
                if c and not is_grease(c) then curves[#curves + 1] = c end
            end
        end
    end

    -- ec_point_formats (ext 11): 1-byte list-length + 1-byte values
    local fmts  = {}
    local fdata = ssl_clt.get_client_hello_ext(11)
    if fdata and #fdata >= 1 then
        local flen = string.byte(fdata, 1)
        if flen then
            for i = 1, flen do
                local f = string.byte(fdata, 1 + i)
                if f then fmts[#fmts + 1] = f end
            end
        end
    end

    local ja3_str = table.concat({
        tls_ver,
        table.concat(ciphers, "-"),
        table.concat(exts,    "-"),
        table.concat(curves,  "-"),
        table.concat(fmts,    "-"),
    }, ",")

    return ngx.md5(ja3_str), ja3_str
end

return _M
