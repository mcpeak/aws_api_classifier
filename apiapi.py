"""
    Usage:
        apiapi.py (all|mutating) [--csv=output_file]
        apiapi.py create_service_score_file <output_file>
        apiapi.py score_all_permissions <service_score_file> <output_file>
"""

import csv
from policyuniverse import global_permissions
import re
import sys
from tabulate import tabulate


TAGS = {
    'DATA_PLANE': ['object', 'bucket'],
    'CONTROL_PLANE': ['policy', 'attribute', 'permission'],
    'MUTATING': ['create', 'delete', 'modify', 'add', 'remove', 'set', 'update', 'put'],
    'READ': ['get', 'view', 'list', 'describe'],
    'SIDE_EFFECT': ['start', 'stop', 'export', 'request', 'resend', 'cancel', 'continue', 'estimate', 'execute', 'preview']
}

CRITICALITY_RATINGS = {'UNDEFINED': 5, 'LOW': 2, 'MEDIUM': 5, 'HIGH': 10}
DEFAULT_VALUE = 'UNDEFINED'

permissions = dict()
for service_name, service_description in global_permissions.items():
    service = service_description['StringPrefix']
    permissions[service] = dict()
    for action in service_description['Actions']:

        action_words = re.findall('[A-Z][^A-Z]*', action)
        action_words = [word.lower() for word in action_words]
        permissions[service][action] = set()

        for tag_name, matches in TAGS.items():
            for match in matches:
                try:
                    if match in action_words:
                        permissions[service][action].add(tag_name)
                except IndexError:
                    if action.lower().startswith(match):
                        permissions[service][action].add(tag_name)

headers = ['service', 'permission']
headers.extend(TAGS.keys())


def create_permissions_table():
    rows = []
    for service, actions in permissions.items():
        for action, tags in actions.items():
            row = [service, action]

            for tag in TAGS.keys():
                row.append(tag in tags)

            rows.append(row)
    return rows


def create_mutating_table():
    """ Filters permissions by MUTATING or SIDE_EFFECT tag. """
    rows = []
    for service, actions in permissions.items():
        for action, tags in actions.items():
            row = [service, action]

            for tag in TAGS.keys():
                row.append(tag in tags)

            # CONTROL_PLANE && (MUTATING or SIDE_EFFECT)
            # if 'CONTROL_PLANE' in tags:
            if 'MUTATING' in tags:
                rows.append(row)
            if 'SIDE_EFFECT' in tags:
                rows.append(row)
    return rows


def create_service_score_file(output_file):
    all_services = set()
    for _, service_description in global_permissions.items():
        all_services.add(service_description['StringPrefix'])

    all_services = sorted(all_services)
    rows = ['{},{}\n'.format(service_name, DEFAULT_VALUE) for service_name in all_services]
    try:
        with open(output_file, 'w') as f:
            f.writelines(rows)
    except IOError:
        print("Unable to write file: {}".format(output_file))
    else:
        print("Sucessfully wrote file: {}".format(output_file))


def score_all_permissions(service_score_file, output_file):
    """
    Take base criticality rating defined in CRITICALITY_RATINGS and add 5 if mutating, this algorithm is basic and
    should undoubtedly be tweaked
    """
    service_criticality_scores = {}
    try:
        with open(service_score_file, 'r') as f:
            for service_line in f.readlines():
                parts = service_line.strip().split(',')
                try:
                    service_criticality_scores[parts[0]] = CRITICALITY_RATINGS[parts[1]]
                except (IndexError, KeyError):
                    print "Ignoring malformed line: {}".format(service_line)

    except IOError:
        print "Unable to read file {}".format(service_score_file)
        sys.exit(1)

    else:
        rows = create_permissions_table()
        new_rows = []
        # skip header row
        for row in rows:
            score = 0
            if len(row) != 7:
                print("Skipping malformed row: {}".format(row))
                continue
            try:
                score = service_criticality_scores[row[0]]
                # mutating adds 5
                if row[3]:
                    score += 5

            except KeyError:
                print("Found a service with no criticality score")
                score = 'UNKNOWN'
            row_with_score = list(row)
            row_with_score.append(score)
            new_rows.append(row_with_score)
        output_csv(output_file, new_rows)


def output_csv(filename, rows):
    with open(filename, 'wb') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(headers)
            for row in rows:
                csv_writer.writerow(row)


if __name__ == '__main__':
    from docopt import docopt
    args = docopt(__doc__, version="APIAPI 1.0")
    if args.get('mutating') or args.get('all'):
        filename = args.get('--csv')
        if args.get('mutating'):
            rows = create_mutating_table()
        elif args.get('all'):
            rows = create_permissions_table()

        if filename:
            output_csv(filename, rows)
        else:
            print tabulate(rows, headers=headers)

    elif args.get('create_service_score_file'):
        create_service_score_file(args.get('<output_file>'))

    elif args.get('score_all_permissions'):
        score_all_permissions(args.get('<service_score_file>'), args.get('<output_file>'))
