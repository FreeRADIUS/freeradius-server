Example configuration for logstash/elasticsearch
================================================

So you've got all these RADIUS logs, but how do you analyse them? What is the
easiest way to query the logs, find out when a client connected or disconnected,
or view the top ten clients logging into the system over the last six hours?

The elastic stack is designed and built to do just that. elasticsearch is a
search engine; logstash is commonly used to feed data in, and kibana the web
interface to query the logs in near real time.

Installing the elastic stack is beyond the scope of this document, but can be done
in a short amount of time by any competent sysadmin. Then comes getting the
logs in.

This directory contains the following files as a starting point for feeding
RADIUS logs into elasticsearch via logstash, then sample dashboards for Kibana
to explore the data.

Files
-----

Please note that all files should be reviewed before use to determine if they
are suitable for your configuration/system, especially if you are integrating
this into an existing logstash/elasticsearch setup.

radius-mapping.sh

  Each elasticsearch index needs a mapping to describe how fields are stored.
  If one is not provided then all is not lost as elasticsearch will build one
  on the fly. However, this may not be optimal, especially for RADIUS data, as
  all fields will be analyzed making some visualisations hard or impossible
  (such as showing top N clients).

  This shell script (which just runs curl) pushes a template mapping into the
  elasticsearch cluster.

logstash-radius.conf

  A sample configuration file for logstash that parses RADIUS 'detail' files.
  It processes these by joining each record onto one line, then splitting the
  tab-delimited key-value pairs out. Some additional data is then extracted
  from certain key attributes.

  The logstash config will need to be edited at least to set the input method:
  for experimentation the given input (file) may be used. If logstash is running
  on the RADIUS server itself then this example input may be appropriate,
  otherwise a different input such as log-courier or filebeat may be better to
  get the data over the network to logstash.

  It would be best to use an input method that can join the multiple lines of
  the detail file together and feed them to logstash as a single entry, rather
  than using the logstash multiline codec.

log-courier.conf

  An example configuration for the log-courier feeder.

kibana4-dashboard.json

  Basic RADIUS dashboard for Kibana 4 and Kibana 5.

  To import the dashboard first create a new index called "radius-*" in
  Settings/Indices. Then go to Kibana's Settings page, "Objects" and "Import".
  Once imported open the "RADIUS detail" dashboard.


Example usage
-------------

Install mapping (only needs to be done once):

    $ ./radius-mapping.sh

Edit logstash-radius.conf to point to the correct file, then feed a detail file
in:

    # /usr/share/logstash/bin/logstash --path.settings=/etc/logstash -f logstash-radius.conf


See also
--------

elasticsearch web site: http://www.elastic.co/

The configuration examples presented here have been tested with the
following software versions (note that elasticsearch 2.x may not yet
work with this config).

  elasticsearch 5.1.2
  logstash 5.1.2
  kibana 5.1.2
  kibana 4.1.11

Matthew Newton
January 2017

