-- Based on https://github.com/bambattajb/openresty-api-example

-- Helper functions
function strSplit(delim,str)
    local t = {}

    for substr in string.gmatch(str, "[^".. delim.. "]*") do
        if substr ~= nil and string.len(substr) > 0 then
            table.insert(t,substr)
        end
    end

    return t
end

-- Read body being passed
-- Required for ngx.req.get_body_data()
ngx.req.read_body()
-- Parser for sending JSON back to the client
local cjson = require("cjson")
-- Get the request path
local reqPath = ngx.var.uri
-- Get the request method (POST, GET etc..)
local reqMethod = ngx.var.request_method
-- Get any URI arguments
local uriArgs = ngx.req.get_uri_args()
-- Parse the body data as JSON
local body = ngx.req.get_body_data() ==
        -- This is like a ternary statement for Lua
        -- It is saying if doesn't exist at least
        -- define as empty object
        nil and {} or cjson.decode(ngx.req.get_body_data());

Api = {}
Api.__index = Api
-- Declare API not yet responded
Api.responded = false;
-- Function for checking input from client
function Api.endpoint(method, path, callback)

    -- return false if method doesn't match
    if reqMethod ~= method
    then
        return false
    end

    -- If API already responded
    if Api.responded then
        return false
    end

    -- KeyData = params passed in path
    local keyData = {}
    -- Unaltered version of path
    local origPath = reqPath
    -- If this endpoint has params
    if string.find(path, "<(.-)>")
    then
        -- Split origin and passed path sections
        local splitPath = strSplit("/", path)
        local splitReqPath = strSplit("/", reqPath)
        -- Iterate over splitPath
        for i, k in pairs(splitPath) do
            -- If chunk contains <something>
            if string.find(k, "<(.-)>")
            then
                if not splitReqPath[i] then
                    reqPath = origPath
                    return false
                end
                -- Add to keyData
                keyData[string.match(k, "%<(%a+)%>")] = splitReqPath[i]
                -- Replace matches with default for validation
                reqPath = string.gsub(reqPath, splitReqPath[i], k)
            end
        end
    end

    -- return false if path doesn't match anything
    if reqPath ~= path
    then
        reqPath = origPath
        return false;
    end

    -- Make sure we don't run this again
    Api.responded = true;

    return callback(body, keyData);
end

-- Used in the accounting test
Api.endpoint('POST', '/user/<username>/mac/<client>',
    function(body, keyData)
        local returnData = {}
        returnData["control:Tmp-String-0"] = uriArgs.section
        returnData["control:Tmp-String-1"] = {
            reqMethod,
            reqPath
        }
        returnData["control:User-Name"] = {
            op = ":=",
            value = keyData.username
        }
        returnData["control:NAS-IP-Address"] = {
            op = "+=",
            value = body.NAS or body['NAS-IP-Address'].value
        }
        returnData["control:Tmp-String-2"] = {
            op = "^=",
            value = keyData.username
        }
        return ngx.say(cjson.encode(returnData))
    end
)

-- Used in the authorize test
Api.endpoint('GET', '/user/<username>/mac/<client>',
    function(body, keyData)
        local returnData = {}
        returnData["control:Tmp-String-0"] = uriArgs.section
        returnData["control:Tmp-String-1"] = {
            reqMethod,
            reqPath
        }
        returnData["control:User-Name"] = {
            op = ":=",
            value = keyData.username
        }
        returnData["control:Tmp-String-2"] = {
            op = "^=",
            value = keyData.username
        }
        return ngx.say(cjson.encode(returnData))
    end
)

-- Simple reflection of a URI argument
Api.endpoint('GET', '/user/<username>/reflect/',
    function(body, keyData)
        local returnData = {}
        returnData["station"] = uriArgs.station
        return ngx.say(cjson.encode(returnData))
    end
)
