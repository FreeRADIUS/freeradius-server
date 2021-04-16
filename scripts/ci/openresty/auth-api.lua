-- Simple API for checking POST data

-- Get the request path
local reqPath = ngx.var.uri
-- Get the request method (POST, GET etc..)
local reqMethod = ngx.var.request_method
-- Get any URI arguments
local uriArgs = ngx.req.get_uri_args()
-- Get any POST arguments
ngx.req.read_body()
local postArgs = ngx.req.get_post_args()

-- We only reply to POST requests
if reqMethod ~= "POST"
then
    return false
end

ngx.say("Section: ", uriArgs.section, ", User: ", postArgs.user, ", Authenticated: true")
