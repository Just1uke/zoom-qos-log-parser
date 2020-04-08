# -*- coding: utf-8 -*-

import csv
import codecs
from datetime import datetime, timedelta
import re
from uuid import uuid4
import argparse
import os
import logging
import sys


class Parser(object):
    PARSE_LOGS = 0x00
    DUMP_PUBLIC_IPS = 0x01
    DUMP_PRIVATE_IPS = 0x02
    DUMP_PARTICIPANTS_BY_PUBLIC_IP = 0x03
    DUMP_PARTICIPANTS_BY_PRIVATE_IP = 0x04
    DUMP_PARTICIPANTS_LIST = 0x05
    DUMP_PARTICIPANTS_LIST_WITH_IPS = 0x06

    def __init__(self, input_files=[], output_directory='./', actions=[PARSE_LOGS]):
        self.input_files = input_files
        self.output_directory = output_directory

        self.public_ip_addresses = {}
        self.private_ip_addresses = {}
        self.participants = {}
        self.meetings = {}
        self.session_logs = []
        self.events = []

        self.parse_input_files()

        self.start_time = self.find_start_time()
        self.end_time = self.find_end_time()
        self.current_timestamp = self.start_time

        while True:
            for event in self.find_events_at_timestamp(self.current_timestamp):
                self.events.append(event)
            if self.current_timestamp == self.end_time:
                break
            else:
                self.current_timestamp = self.find_next_timestamp(self.current_timestamp)

        self.events.sort(key=lambda x: x['event_time'])

        for action in actions:
            if action == Parser.PARSE_LOGS:
                self.write_output_file()
                self.output_log_stats()
            elif action == Parser.DUMP_PUBLIC_IPS:
                self.dump_public_ips()
            elif action == Parser.DUMP_PRIVATE_IPS:
                self.dump_private_ips()
            elif action == Parser.DUMP_PARTICIPANTS_BY_PUBLIC_IP:
                self.dump_participants_by_public_ip()
            elif action == Parser.DUMP_PARTICIPANTS_BY_PRIVATE_IP:
                self.dump_participants_by_private_ip()
            elif action == Parser.DUMP_PARTICIPANTS_LIST:
                self.dump_participants_list()
            elif action == Parser.DUMP_PARTICIPANTS_LIST_WITH_IPS:
                self.dump_participants_list_with_ips()
            logger.info('\r\n\r\n')

    def parse_input_files(self):
        for file in self.input_files:
            file_contents = self.get_input_file_contents(file)
            meeting_uuid = str(uuid4())
            self.meetings[meeting_uuid] = Parser.parse_out_meeting_information(file_contents)
            self.session_logs = self.session_logs + self.parse_out_session_logs(file_contents, meeting_uuid)

    def dump_public_ips(self):
        logger.info('Public IP Addresses:')
        for item in self.public_ip_addresses:
            logger.info(f"\t{item}")

    def dump_private_ips(self):
        logger.info('Private IP Addresses:')
        for item in self.private_ip_addresses:
            logger.info(f"\t{item}")

    def dump_participants_by_public_ip(self):
        logger.info('Participants by Public IP Address:')
        for ip_address in self.public_ip_addresses:
            logger.info(f'\t{ip_address}')
            for participant in self.public_ip_addresses[ip_address]['participants']:
                logger.info(f'\t\t{participant}')

    def dump_participants_by_private_ip(self):
        logger.info('Participants by Private IP Address:')
        for ip_address in self.private_ip_addresses:
            logger.info(f'\t{ip_address}')
            for participant in self.private_ip_addresses[ip_address]['participants']:
                logger.info(f'\t\t{participant}')

    def dump_participants_list(self):
        logger.info('Participants List:')
        for participant in self.participants:
            logger.info(f"\t{participant}")

    def dump_participants_list_with_ips(self):
        logger.info('Participants List with IP Addresses:')
        for participant in self.participants:
            logger.info(f"\t{participant}")
            logger.info(f"\t\tPublic IP Addresses:")
            for public_ip in self.participants[participant]['public_ip_addresses']:
                logger.info(f"\t\t\t{public_ip}")
            logger.info(f"\t\tPrivate IP Addresses:")
            for private_ip in self.participants[participant]['private_ip_addresses']:
                logger.info(f"\t\t\t{private_ip}")

    def write_output_file(self):
        self.ensure_output_directory_exists()

        filename_base = f'{datetime.strftime(self.start_time, "%m%d%Y%H%M%S")}-{datetime.strftime(self.end_time, "%m%d%Y%H%M%S")}'

        meeting_information_file = os.path.join(self.output_directory, f"{filename_base}_meeting_info.txt")
        events_file = os.path.join(self.output_directory, f"{filename_base}_events.csv")

        logger.info(f'Writing meeting information: {meeting_information_file}')
        keys = self.meetings[list(self.meetings.keys())[0]].keys()
        with open(meeting_information_file, 'w') as output_file:
            for meeting in self.meetings:
                for key in self.meetings[meeting]:
                    output_file.write(f"{key}: {self.meetings[meeting][key]}\r\n")
                output_file.write("\r\n\r\n")

        logger.info(f'Writing meeting events file: {events_file}')
        keys = self.events[0].keys()
        with open(events_file, 'w') as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(self.events)

    def output_log_stats(self):
        logger.info(f'Number of events identified: {len(self.session_logs)}')
        logger.info(f'Number of sessions identified: {len(self.events)}')

        logger.info(f'Number of Public IP addresses seen: {len(self.public_ip_addresses)}')
        logger.info(f'Number of Local IP addresses seen: {len(self.private_ip_addresses)}')

        logger.info(f'Number of participants names seen: {len(self.participants)}')

        logger.info(f"Earliest event time: {self.start_time}")
        logger.info(f"Latest event time: {self.end_time}")

    def ensure_output_directory_exists(self):
        logger.debug(f'Ensuring that output directory exists: {self.output_directory}')
        if not os.path.exists(self.output_directory):
            logger.debug('Output directory does not exist. Creating it.')
            os.makedirs(self.output_directory)

    def parse_out_session_logs(self, file_contents, meeting_uuid):
        logger.debug('Parsing out session logs')
        session_logs = []

        # Skip the first two rows in our exported CSV file, as they contain meeting information.
        reader = csv.DictReader(file_contents.split("\r\n")[3:], delimiter=',')
        for row in reader:
            session_logs.append(row)

        session_logs = Parser.transform_keys_for_logs(session_logs)

        for log in session_logs:
            # Here we're just going to cover our eyes and pretend that meetings wont last more than one day
            log['join_time'] = datetime.combine(self.meetings[meeting_uuid]['start_time'].date(),
                                                datetime.strptime(log['join_time'], '%I:%M %p').time())

            time_extraction = re.match(r"(?P<time>\d\d:\d\d [AaPp][Mm])\((?P<disconnect_reason>.*)\)",
                                       log['leave_time'])

            log['leave_time'] = datetime.combine(self.meetings[meeting_uuid]['start_time'].date(),
                                                 datetime.strptime(time_extraction.group('time'), '%I:%M %p').time())

            log['disconnect_reason'] = time_extraction.group('disconnect_reason')

            ip_address_extraction = re.match(
                r"^Public IP: (?P<public_ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}) Local IP: (0.0.0.0,)?(?P<private_ip>.*$)",
                log['ip_address'])

            # Extract the public IP address and add it to the public IP addresses dict
            log['public_ip'] = ip_address_extraction.group('public_ip')
            self.public_ip_addresses.setdefault(log['public_ip'], {
                'participants': set(),
                'private_ip_addresses': set(),
            })
            # Add the seen participant to the public IP address dict
            self.public_ip_addresses[log['public_ip']]['participants'].add(log['participant'])

            # Extract the private IP address and add it to out private IP addresses dict
            log['private_ip'] = ip_address_extraction.group('private_ip')
            self.private_ip_addresses.setdefault(log['private_ip'], {
                'participants': set(),
                'public_ip_addresses': set(),
            })
            # Add the seen participant to the private IP address dict
            self.private_ip_addresses[log['private_ip']]['participants'].add(log['participant'])

            # Add the public <-> private IP address mapping
            self.public_ip_addresses[log['public_ip']]['private_ip_addresses'].add(log['private_ip'])
            self.private_ip_addresses[log['private_ip']]['public_ip_addresses'].add(log['public_ip'])

            # Add the participant to the participants dict
            self.participants.setdefault(log['participant'], {
                'private_ip_addresses': set(),
                'public_ip_addresses': set(),
            })

            # Add any seen public or private IP addresses to the participant
            self.participants[log['participant']]['public_ip_addresses'].add(log['public_ip'])
            self.participants[log['participant']]['private_ip_addresses'].add(log['private_ip'])

            log['session_key'] = str(uuid4())

        return session_logs

    @staticmethod
    def parse_out_meeting_information(file_contents):
        meeting_information = None

        # The first two lines of our exported CSV file contain the meeting information.
        reader = csv.DictReader(file_contents.split("\r\n")[0:2], delimiter=',')
        for row in reader:
            meeting_information = row

        # Convert our keys into something a little more computer friendly.
        meeting_information = Parser.transform_keys_for_log(meeting_information)

        # Parse out the Start Time into a usable timestamp
        Parser.convert_field_to_timestamp_for_log(meeting_information, 'start_time', "%b %d, %Y %I:%M %p")

        # Parse out Meeting Duration and convert it into a TimeDelta for use in calculating EndTime
        (dur_hh, dur_mm, dur_ss) = meeting_information['duration_hh_mm_ss'].split(":")
        meeting_information['duration_hh_mm_ss'] = timedelta(hours=int(dur_hh),
                                                             minutes=int(dur_mm),
                                                             seconds=int(dur_ss))

        # Replace End Time with a calculated timestamp. Don't trust End Time from the export, as it's reported as hh:mm
        # for whatever reason
        meeting_information['end_time'] = meeting_information['start_time'] + meeting_information['duration_hh_mm_ss']

        return meeting_information

    def read_input_file(self, data_file):
        logs = csv.DictReader(codecs.EncodedFile(data_file, 'utf8', 'utf_8_sig'))
        # logs = LogSorter.transform_keys(logs)
        # logs = LogSorter.convert_field_to_timestamp(logs, 'join_time')
        # logs = LogSorter.convert_field_to_timestamp(logs, 'leave_time')
        # logs = LogSorter.add_session_key(logs)
        return logs

    def get_input_file_contents(self, input_file):
        with codecs.EncodedFile(open(input_file, 'rb'), 'utf8', 'utf_8_sig') as fp:
            file_contents = fp.read()
        return file_contents.decode()

    @staticmethod
    def transform_keys_for_logs(logs):
        new_logs = []
        for log in logs:
            new_dict = Parser.transform_keys_for_log(log)
            new_logs.append(new_dict)
        return new_logs

    @staticmethod
    def transform_keys_for_log(log):
        new_dict = {}
        for old_key in log:
            if not old_key:
                old_value = log[old_key]
                old_key = "other_1"
            else:
                old_value = log[old_key]

            new_key = old_key.lower().replace(' ', '_').replace('(', '').replace(')', '').replace(':', '_').replace('-',
                                                                                                                    '_')
            new_dict[new_key] = old_value
        return new_dict

    @staticmethod
    def convert_fields_to_timestamp_for_logs(logs=[], keys=[], timestamp_format="%m/%d/%Y:%X"):
        for log in logs:
            for key in keys:
                log[key] = Parser.convert_field_to_timestamp_for_log(log, key, timestamp_format)
        return logs

    @staticmethod
    def convert_field_to_timestamp_for_logs(logs, key, timestamp_format="%m/%d/%Y:%X"):
        for log in logs:
            log[key] = Parser.convert_field_to_timestamp_for_log(log, key, timestamp_format)
        return logs

    @staticmethod
    def convert_fields_to_timestamp_for_log(log, keys=[], timestamp_format="%m/%d/%Y:%X"):
        for key in keys:
            log = Parser.convert_field_to_timestamp_for_log(log, key, timestamp_format)
        return log

    @staticmethod
    def convert_field_to_timestamp_for_log(log, key, timestamp_format="%m/%d/%Y:%X"):
        log[key] = datetime.strptime(log[key], timestamp_format)
        return log

    def find_start_time(self):
        start_time = None
        for log in self.session_logs:
            if start_time is None or log['join_time'] < start_time:
                start_time = log['join_time']
            if log['leave_time'] < start_time:
                start_time = log['leave_time']
        return start_time

    def find_end_time(self):
        end_time = None
        for log in self.session_logs:
            if end_time is None or log['join_time'] > end_time:
                end_time = log['join_time']
            if log['leave_time'] > end_time:
                end_time = log['leave_time']
        return end_time

    def find_events_at_timestamp(self, timestamp):
        finds = []
        for log in self.session_logs:
            event_type = None
            event_time = None
            find = None

            if log['join_time'] == timestamp:
                event_type = 'Session Created'
                event_time = log['join_time']
            if log['leave_time'] == timestamp:
                event_type = 'Session Destroyed'
                event_time = log['leave_time']

            if event_type and event_time:
                find = log.copy()
                find['event_type'] = event_type
                find['event_time'] = event_time
                finds.append(find)

        return finds

    def find_next_timestamp(self, last_time_stamp):
        next_time_stamp = None
        for log in self.session_logs:
            if log['join_time'] > last_time_stamp:
                if next_time_stamp is None or log['join_time'] < next_time_stamp:
                    next_time_stamp = log['join_time']

            if log['leave_time'] > last_time_stamp:
                if next_time_stamp is None or log['leave_time'] < next_time_stamp:
                    next_time_stamp = log['leave_time']
        return next_time_stamp


if __name__ == "__main__":
    arguments = argparse.ArgumentParser(description='Parses Zoom QOS Logs into a usable format')
    arguments.add_argument('input_files', nargs='+', help='The script to run')
    arguments.add_argument('-o', '--output', help='Output directory', default='./')
    arguments.add_argument(
        '-d', '--debug',
        help="Print debug information",
        action="store_const", dest="loglevel", const=logging.DEBUG,
    )

    arguments.add_argument(
        '-q', '--quiet',
        help="Suppress all output",
        action="store_true",
        default=False
    )

    arguments.add_argument('--parse-logs', dest='actions', action='append_const', const=Parser.PARSE_LOGS,
                           help="Parse logs and write them to the output directory specified by -o.")
    arguments.add_argument('--dump-public-ips', dest='actions', action='append_const', const=Parser.DUMP_PUBLIC_IPS,
                           help="Dumps the identified public IP addresses")
    arguments.add_argument('--dump-private-ips', dest='actions', action='append_const', const=Parser.DUMP_PRIVATE_IPS,
                           help="Dumps the identified private IP addresses")
    arguments.add_argument('--dump-participants-by-public-ip', dest='actions', action='append_const',
                           const=Parser.DUMP_PARTICIPANTS_BY_PUBLIC_IP,
                           help="Dumps the identified participants by public IP address")
    arguments.add_argument('--dump-participants-by-private-ip', dest='actions', action='append_const',
                           const=Parser.DUMP_PARTICIPANTS_BY_PRIVATE_IP,
                           help='Dumps the identified participants by private IP address')
    arguments.add_argument('--dump-participants-list', dest='actions', action='append_const',
                           const=Parser.DUMP_PARTICIPANTS_LIST, help="Dumps the identified participants")
    arguments.add_argument('--dump-participants-list-with-ips', dest='actions', action='append_const',
                           const=Parser.DUMP_PARTICIPANTS_LIST_WITH_IPS,
                           help="Dumps the identified participants with the IP addresses they used")

    arguments.add_argument('--all-actions', dest='actions', action='store_const', const=[Parser.PARSE_LOGS,
                                                                                         Parser.DUMP_PUBLIC_IPS,
                                                                                         Parser.DUMP_PRIVATE_IPS,
                                                                                         Parser.DUMP_PARTICIPANTS_BY_PUBLIC_IP,
                                                                                         Parser.DUMP_PARTICIPANTS_BY_PRIVATE_IP,
                                                                                         Parser.DUMP_PARTICIPANTS_LIST,
                                                                                         Parser.DUMP_PARTICIPANTS_LIST_WITH_IPS])

    arguments.set_defaults(loglevel=logging.INFO,
                           actions=[Parser.PARSE_LOGS])

    args = arguments.parse_args()

    # create logger
    logger = logging.getLogger()
    logger.setLevel(args.loglevel)

    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(message)s')

    if not args.quiet:
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setLevel(args.loglevel)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    Parser(args.input_files, args.output, args.actions)
