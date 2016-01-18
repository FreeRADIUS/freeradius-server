#! /bin/sh

# Create a template mapping for RADIUS data
# Matthew Newton
# April 2015

# This should be run on an elasticsearch node. Alternatively,
# adjust the curl URI below.

# The template will be called "radius", and will apply to all
# indices prefixed with "radius-" that contain data type "detail".
# As not all RADIUS attributes are known to begin with it has the
# following starting point that can be modified to suit the local
# configuration:
#
#   Acct-Input- or Acct-Output- attributes are numbers;
#   Acct-Session-Time is a number;
#   Everything else is a string.

# Additionally, the supplied logstash config will try and extract
# MAC addresses, IP addresses and ports from the data. These are
# stored with suffixes on the respective attribute. For example,
# an attribute
#
#   Called-Station-Id := "10.0.4.6[4500]"
#
# will be broken down into the following fields in elasticsearch:
#
#   Called-Station-Id = "10.0.4.6[4500]"
#   Called-Station-Id_ip = "10.0.4.6"
#   Called-Station-Id_port = "4500"
#
# This mapping ensures that these have an appropriate data type.


curl -XPUT '127.0.0.1:9200/_template/radius' -d '
{
  "template":"radius-*",
  "order":0,
  "mappings":{
    "detail":{

      "properties": {
        "@timestamp": { "format": "dateOptionalTime", "type": "date" },
        "@version": { "type" : "string" },
        "message": { "type" : "string" },
        "Acct-Session-Time": { "type" : "long", "doc_values": true },
        "offset": { "type" : "long", "doc_values": true }
      },

      "dynamic_templates": [

        { "acct_io_numbers": {
            "match_pattern": "regex",
            "match": "^Acct-(Input|Output)-.*$",
            "mapping": {
              "type": "long",
              "doc_values": true
            }
          }
        },

        { "ipv4_address": {
            "path_match": "*_ip",
            "mapping": {
              "type": "ip",
              "doc_values": true
            }
          }
        },

        { "network_port": {
            "path_match": "*_port",
            "mapping": {
              "type": "integer",
              "doc_values": true
            }
          }
        },

        { "long_number": {
            "path_match": "*_long",
            "mapping": {
              "type": "integer",
              "doc_values": true
            }
          }
        },

        { "no_analyze_strings": {
            "match": "*",
            "mapping": {
              "type": "string",
              "index": "not_analyzed",
              "doc_values": true
            }
          }
        }

      ]
    }
  }
}'
