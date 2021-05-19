from argparse import ArgumentParser


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('host', help='Specify hostname for tracing')
    return parser.parse_args()
