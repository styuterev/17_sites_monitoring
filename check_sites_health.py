import argparse
import datetime
import os
import requests
import urllib.parse
import whois
import logging


def load_urls4check(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding='UTF8') as url_file:
        for url in url_file.readlines():
            yield url.strip('\n')


def get_domain_name(url):
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.netloc


def is_server_respond_with_200(url):
    try:
        response = requests.get(url)
    except:  # WORKAROUND !!!
        logger.error('Problem with connection')
        return False
    return response.status_code == 200


def get_domain_expiration_date(domain_name):
    try:
        domain = whois.whois(domain_name).expiration_date
    except:  # WORKAROUND !!!
        logger.error('Problem with WhoIs servers')
        return None
    if isinstance(domain, list):
        domain = domain[0]  # some sites provide lists of dates
    return domain


def check_site_status(path):
    for url in load_urls4check(path):
        domain_name = get_domain_name(url)
        respond_with_200 = is_server_respond_with_200(url)
        expiration_date = get_domain_expiration_date(domain_name)
        yield domain_name, respond_with_200, expiration_date


def emergency_exit(path):
    if path is None:
        print('You forgot to send file path as a parameter.')
        raise SystemExit
    if load_urls4check(path) is None:
        print('Not possible to open file with the provided path')
        raise SystemExit


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', action='store',
                        help='path to the file containing sites\' urls')
    return parser.parse_args()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info('Program started')
    arguments = parse_arguments()
    path = arguments.path
    emergency_exit(path)
    for status in check_site_status(path):
        domain_name, is_status_200, expiration_date = status
        logger.debug('Working with {}'.format(domain_name))
        output_string = 'Domain: {}\nResponds with 200: {}\nDomain expires on: {}\n'\
            .format(domain_name, is_status_200, expiration_date)
        print(output_string)
    logger.info('Program finished')
