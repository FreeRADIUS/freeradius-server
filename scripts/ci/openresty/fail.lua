-- API which will return code 400 with a JSON formatted error message

ngx.status = ngx.HTTP_BAD_REQUEST
ngx.say('{"error": "Invalid request"}')
return ngx.exit(ngx.HTTP_BAD_REQUEST)
