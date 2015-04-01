#! /bin/sh

# Create a template mapping for RADIUS data
# Matthew Newton
# April 2015

# This should be run on an elasticsearch node. Alternatively, adjust
# the curl URI below.

curl -XPUT '127.0.0.1:9200/_template/radius' -d '
{
  "template":"radius-*",
  "order":0,
  "mappings":{
    "detail":{
      "dynamic_templates":[
        { "keep_message":{
            "match":"message",
            "mapping":{
              "type":"string",
              "index":"analyzed"
            }
          }
        },
        { "no_analyze_strings":{
            "match":"*",
            "match_mapping_type":"string",
            "mapping":{
              "type":"string",
              "index":"not_analyzed"
            }
          }
        }
      ]
    }
  }
}'

