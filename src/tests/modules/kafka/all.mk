#
#  Test the "kafka" module.
#
#  Skipped unless KAFKA_TEST_SERVER is set in the environment.  CI provides it
#  via the Redpanda service declared in .github/workflows/ci.yml.
#
#  For local development:
#
#      docker run --rm -d --name fr-kafka -p 9092:9092 \
#          docker.redpanda.com/redpandadata/redpanda:latest
#      KAFKA_TEST_SERVER=127.0.0.1 make test.modules.kafka
#      docker stop fr-kafka
#
#  librdkafka auto-creates topics on first produce, so there is no setup
#  script (unlike ldap / 389ds / mysql).
#
kafka_require_test_server := 1

#
#  Absolute path to the kafka-subscribe helper, exported into the
#  environment so every .unlang test can invoke it via
#  %exec('$ENV{KAFKA_SUBSCRIBE}', ...) to capture what the broker
#  actually saw and diff it against what was produced.
#
export KAFKA_SUBSCRIBE         := $(top_srcdir)/scripts/ci/kafka-subscribe.sh
export KAFKA_WAIT_AND_CLEANUP  := $(top_srcdir)/scripts/ci/kafka-wait-and-cleanup.sh
