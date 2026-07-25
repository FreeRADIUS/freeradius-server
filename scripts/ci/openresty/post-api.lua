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

-- Used in the do_xlat section default tests.  Returns a urlencoded
-- attribute whose value contains an xlat expansion ("%{User-Name}"),
-- so the tests can verify whether the server expanded the value.
-- ngx.print is used as the POST decoder would include a trailing
-- newline in the value.
if uriArgs.expand then
    return ngx.print("control%3ATmp-String-3=%25%7BUser-Name%7D")
end

ngx.say("Section: ", uriArgs.section, ", User: ", postArgs.user)
