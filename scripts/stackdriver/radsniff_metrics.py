#!python3
import atexit
import csv
import logging
import math
import os
import pty
import re
import subprocess

import opencensus.stats.stats

import opencensus.ext.stackdriver.stats_exporter
import yaml

from opencensus.ext import prometheus
from opencensus.ext.prometheus import stats_exporter
from opencensus.stats.stats import stats
from opencensus.stats import view, measure, aggregation
# from opencensus.tags import tag_key, tag_map, tag_value

# Make up for broken code in the Prometheus exporter
import opencensus.stats.aggregation_data
opencensus.stats.aggregation_data.SumAggregationDataFloat = opencensus.stats.aggregation_data.SumAggregationData

SUPPORTED_EXPORTERS = ['Prometheus', 'Stackdriver']


class BaseStatistic:
    def __init__(self, config=None, tag_keys=None):
        logging.info(f"Entering BaseStatistic.__init__({config}, {tag_keys}")
        if config is None:
            config = {}
        if tag_keys is None:
            tag_keys = []

        self.name = config.get('name', '')
        self.description = config.get('description', 'unspecified')
        self.unit = config.get('unit', '1')

        logging.debug(f"Creating a measurement for {self.name}, {self.description}, {self.unit}")
        self.measure = measure.MeasureFloat(
            name=self.name,
            description=self.description,
            unit=self.unit
        )
        logging.debug(f"Creating a new view for {self.name}")
        self.view = view.View(
            name=self.name,
            description=self.description,
            columns=tag_keys,
            aggregation=aggregation.LastValueAggregation(),
            measure=self.measure
        )
        stats.view_manager.register_view(self.view)

    def display_name(self):
        return self.name

    def collect(self, measurement_map=None, value=0.0):
        logging.debug(f"  Entering collect({measurement_map}, {value}) for statistic {self.name}")
        if measurement_map is None:
            logging.error(f"INTERNAL ERROR: Failing to collect statistic {self.display_name()} "
                          f"because no measurement map was supplied.")
            raise ValueError("The measurement map must be supplied to LdapStatistic.collect")
        if math.isnan(value):
            raise ValueError("The value to measure must be a number greater than zero.")
        if value > 0:
            print(f"{self.measure.name}: {value}")
        measurement_map.measure_float_put(self.measure, value)


class RadiusStatistic(BaseStatistic):
    def __init__(self, config=None, tag_keys=None):
        sub_config = {
            'name': config.get('name', ''),
            'description': config.get('description', config.get("label")),
            'unit': config.get('unit', self.guess_unit(config.get('label')))
        }
        super().__init__(sub_config, tag_keys)

    @staticmethod
    def guess_unit(label):
        if re.search(r'/s$', label) or re.search(r'PPS$', label):
            return 's'
        if re.search(r'\(ms\)$', label):
            return 'ms'
        print(f"Could not determine a unit for {label}, using 'By'.")
        return 'By'


def create_exporter(config=None):
    if config is None:
        raise ValueError("Cannot create an exporter with no configuration!")

    name = config.get('name')
    if name not in SUPPORTED_EXPORTERS:
        logging.error(
            f"Requested exporter named {name}, which is not supported.  Choose from:{', '.join(SUPPORTED_EXPORTERS)}"
        )
        raise ValueError(
            f"Requested exporter named {name}, which is not supported.  Choose from:{', '.join(SUPPORTED_EXPORTERS)}"
        )

    exporter = None

    options = config.get('options', {})
    if "Prometheus" == name:
        if 'options' not in config:
            logging.error("The Prometheus exporter requires options configuration.")
            raise ValueError("The Prometheus exporter requires options configuration.")
        final_options = {'namespace': 'radius', 'port': 8001, 'address': '0.0.0.0'}
        final_options.update(options)
        exporter = stats_exporter.new_stats_exporter(
            prometheus.stats_exporter.Options(**final_options)
        )

    elif "Stackdriver" == name:
        exporter = opencensus.ext.stackdriver.stats_exporter.new_stats_exporter(interval=5)
        print(f"Exporting stats to this project {exporter.options.project_id}")

    return exporter


class Configuration:
    def __init__(self, configuration_filename='radsniff_metrics.yml'):
        if configuration_filename is None:
            raise ValueError("Configuration filename must be supplied.")
        self._configuration_filename = configuration_filename
        self._config = {}
        self.read_configuration()

    def exporters(self):
        return {'name': 'Prometheus', 'options': {}}

    def read_configuration(self):
        with open(self._configuration_filename, 'r') as file:
            ret_val = yaml.safe_load(file)
        self._config = ret_val


def main():
    config = Configuration()
    exporter = create_exporter(config.exporters())
    stats.view_manager.register_exporter(exporter)
    master_fd, slave_fd = pty.openpty()
    command_line = ['./radsniff', '-W', '5', '-E']
    process = subprocess.Popen(
        command_line,
        stdout=slave_fd,
        bufsize=1,
        text=True
    )
    atexit.register(exit_handler, process)
    radsniff_output = os.fdopen(master_fd)
    reader = csv.DictReader(radsniff_output)

    statistics = None
    for row in reader:
        logging.info("Read a new set of data from radsniff.")
        measurement_map = stats.stats_recorder.new_measurement_map()
        if statistics is None:
            statistics = {}
            updates = {
                'access-': 'access/',
                'accounting-': 'accounting/',
                'status-': 'status/',
                'disconnect-': 'disconnect/',
                'coa-': 'coa/',
                'request ': 'request/',
                'accept ': 'accept/',
                'reject ': 'reject/',
                'response ': 'response/',
                'challenge ': 'challenge/',
                'server ': 'server/',
                'client ': 'client/',
                'nak ': 'nak/',
                'ack ': 'ack/',
                r'rtx \(([1-5].?)\)': r'rtx/\1',
                ' ': '_',
                r'\+': 'plus',
                '/s$': '',
            }
            for label in row.keys():
                name = label.lower()
                for match, replacement in updates.items():
                    name = re.sub(match, replacement, name)
                statistics[label] = RadiusStatistic(
                    {
                        'label': label.lower(),
                        'name': name,
                        'description': label,
                    },
                    []
                )
        for label, measurement in row.items():
            measurement_value = float(measurement)
            if math.isnan(measurement_value):
                continue

            statistic = statistics.get(label, None)
            if statistic is None:
                logging.error("Tried to collect a value for a name ({label}) that has not been seen before.  Skipping.")
                continue

            statistic.collect(
                measurement_map=measurement_map,
                value=measurement_value
            )
        measurement_map.record()


def exit_handler(process):
    result = process.terminate()


if __name__ == '__main__':
    logging.getLogger().setLevel('WARN')
    main()
