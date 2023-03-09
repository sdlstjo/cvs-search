#!/usr/bin/python
"""
CVE-SEARCH Copyright(C) 2023 Stefan Johansson (stefan@thejohanson.com)

This program comes with ABSOLUTELY NO WARRANTY
for details add `--show_warranty`

This is free software, and you are welcome to
redistribute it under certain conditions
for details add `--show_license`

cve-search is a sample on how to download the allitems.xml cve list, for filtering and other use

This is only partially documented
"""


def lineno():
    """
    Returns the current line number in the program.
    """
    import inspect
    import os
    file_name = os.path.basename(__file__)
    line_num = inspect.currentframe().f_back.f_lineno
    return_string = "File name: " + str(file_name) + " Line num: " + str(line_num) + " output: "
    return return_string


def section(fle, begin, end):
    """

    :param fle:
    :param begin:
    :param end:
    :return:
    """
    with open(fle) as f:
        for line in f:
            # found start of section so start iterating from next line
            if line.strip(" ").startswith(begin):
                # print("Test Print", line)
                for line in f:
                    if line != "\n":
                        # found end so end function
                        if line.strip(" ").startswith(end):
                            return
                        # yield every line in the section
                        yield line.rstrip()


def cmd_arguments():
    """
    Getting all arguments from commandline under one function
    """
    import argparse
    import textwrap
    import sys
    parser = argparse.ArgumentParser(prog="cve-search", formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''\
       cve-search  Copyright (C) 2023  Stefan Johansson
    ------------------------------------------------------
        This program comes with ABSOLUTELY NO WARRANTY
        for details add --show_warranty
        This is free software, and you are welcome
        to redistribute it under certain conditions
        for details add --show_conditions
                 '''))
    # basic Arguments
    parser.add_argument("--screen_output",
                        action="store_true",
                        help="Print messages to screen")
    parser.add_argument("--show_warranty",
                        action="store_true",
                        help="Show Warranty info from license")
    parser.add_argument("--show_conditions",
                        action="store_true",
                        help="Show redistribution conditions")
    parser.add_argument("--cve_download",
                        action="store_true",
                        help="Force new download of all items XML file from cve.org")
    parser.add_argument("--script_arg_test",
                        action="store_true",
                        help="Screen print the command arguments provided")
    # CVE Search of CVE.org
    parser.add_argument("--cve_search",
                        action="store_true",
                        help="Search the cve.org for CVE data")
    parser.add_argument("--cve_name_filter",
                        default="CVE-2023",
                        help="Full or partial CVE id to search for i.e: CVE-2023, searches for all CVE's starting with year 2020")
    parser.add_argument("--cve_description_filter",
                        default="Symantec",
                        help="CVE Org description field search, for example 'Symantec' ")
    parser.add_argument("--cve_save_search",
                        action="store_true",
                        help="Save the search from cve.org to file")
    parser.add_argument("--cve_save_directory",
                        default="cve_searches",
                        help="Directory where to save the CVE searches to")
    # Get detailed CVE information from mitre's CVE repository on github
    parser.add_argument("--cve_save_files",
                        action="store_true",
                        help="Save the individual json files from the search of cve.org")
    parser.add_argument("--cve_file_directory",
                        default="cve_files",
                        help="Directory where to save the individual json files to")
    # Get detailed CVE information from VULNDB.com, requires registration for API key
    parser.add_argument("--vulndb_cve_details",
                        action="store_true",
                        help="Requires API Key: Get detailed CVE Details from vulndb.com and save to json file")
    parser.add_argument("--vulndb_out_dir",
                        default="vulndb_data",
                        help="Directory where CVE detail file from Vulndb.com is stored")
    parser.add_argument("--vulndb_api_key",
                        help="Vulndb.com API key")
    #
    parser.add_argument("--vulndb_in_file",
                        help="Get basic info from saved Vulndb.com output")
    parser.add_argument("--vulndb_out_file",
                        help="Save basic info from saved Vulndb.com output to filename")
    #
    args = vars(parser.parse_args())
    if args['cve_save_search'] and (args['cve_name_filter'] is None or args['cve_description_filter'] is None):
        parser.error(
            'The --cve_save_search argument requires the --cve_name_filter or --cve_description_filter to be provided')
    if args['vulndb_cve_details'] and (args['vulndb_api_key'] is None or not args['cve_save_search']):
        parser.error('The --vulndb_cve_details argument requires the --vulndb_api_key to be provided')
    if (args['vulndb_in_file'] is not None and args['vulndb_out_file'] is None) or (
            args['vulndb_out_file'] is not None and args['vulndb_in_file'] is None):
        parser.error('The --vulndb_in_file & the --vulndb_out_file argument requires the other one to be filled')
    if args['script_arg_test']:
        print(lineno(), json_pretty_print(args))
        exit(0)
    if args['show_warranty']:
        begin = "15. Disclaimer of Warranty."
        end = "16. Limitation of Liability."
        text = list(section(fle="LICENSE", begin=begin, end=end))
        print("#", begin)
        for line in text:
            print("#", line)
        print("#")
        print("#", "For full Licensing information read the LICENSE file")
        exit(0)
    if args['show_conditions']:
        begin = "0. Definitions."
        end = "1. Source Code."
        text = list(section(fle="LICENSE", begin=begin, end=end))
        print("#", begin)
        for line in text:
            print("#", line)
        print("#")
        print("#", "For full Licensing information read the LICENSE file")
        exit(0)
    # print("Number of arguments from command line", len(sys.argv))
    if len(sys.argv) <= 1:
        text = textwrap.dedent('''

           cve-search  Copyright (C) 2023  Stefan Johansson
        ------------------------------------------------------
            no commandline arguments were given
            use "cve-search -h" for help text 
                     ''')
        print(text)
        exit(0)
    text = textwrap.dedent('''\
       cve-search  Copyright (C) 2023  Stefan Johansson
    ------------------------------------------------------
        This program comes with ABSOLUTELY NO WARRANTY
        for details add --show_warranty
        This is free software, and you are welcome
        to redistribute it under certain conditions
        for details add --show_conditions
        
     For full Licensing information read the LICENSE file
                 ''')
    print("")
    print(text)
    print("")
    return args


def get_url(url, method=None, data=None, headers=None, print_screen=False):
    """
    Basic URL Get, Post, Put functions
    """
    import urllib3
    import requests
    if method is None:
        if print_screen:
            print(lineno(), "URL capture method is required")
        exit(1)
    if data is None:
        data = {}
    if headers is None:
        headers = {}
    urllib3.disable_warnings()
    session = requests.Session()
    response = ""
    try:
        response = session.request(url=url, method=method, data=data, headers=headers, verify=False)

    except Exception as e:
        if print_screen:
            print(lineno(), "HTTP(s) response status code", response.status_code)
            print(lineno(), e)
        exit(1)
    return response


def json_pretty_print(json_data, indent=2):
    """
    Screen print "Pretty" JSON data
    :param json_data: The JSON Data object that is "pretty" formatted
    :param indent: The indent for the "pretty" formatting
    :return: The "pretty" formatted JSON string
    """
    import json
    json_pretty = json.dumps(json_data, indent=indent)
    return json_pretty


def open_file(file_name, print_screen=False):
    """
    :param print_screen:
    :param file_name:
    :return: file_as_data
    """
    try:
        with open(file_name) as f:
            file_as_data = f.read()
            f.close()
    except Exception as e:
        if print_screen:
            print(lineno(), e)
        exit(1)
    return file_as_data


def save_file(file_name, data, print_screen=False):
    """
    :param print_screen:
    :param file_name:
    :param data:
    :return: file_as_data
    """
    try:
        with open(file_name, "w") as f:
            f.write(data)
            f.close()
    except Exception as e:
        if print_screen:
            print(lineno(), e)
        exit(1)


def pd_parse(data, data_type, print_screen=False):
    """
    Pandas parse data
    :param print_screen:
    :param data: Data to parse
    :param data_type:
    :return: Parsed data
    """
    import pandas as pd
    try:
        if data_type is None:
            print(lineno(), "Data Type is missing")
            exit(1)
        elif data_type.lower() == "xml":
            parsed_data = pd.read_xml(data)
        elif data_type.lower() == "json_old":
            parsed_data = pd.read_json(data)
        elif data_type.lower() == "html":
            parsed_data = pd.read_html(data)
        elif data_type.lower() == "xls":
            parsed_data = pd.read_excel(data)
        elif data_type.lower() == "csv":
            parsed_data = pd.read_csv(data)
        else:
            if print_screen:
                print(lineno(), "Data Type is not handled by this function")
            exit(1)
    except Exception as e:
        if print_screen:
            print(lineno(), e)
        exit(1)
    return parsed_data


def load_json(data, print_screen=False):
    """

    :param print_screen:
    :param data:
    :return:
    """
    import json
    try:
        if type(data) is str:
            if print_screen:
                print(lineno(), "Data is of format:", type(data))
            json_data = json.loads(data)
        else:
            if print_screen:
                print(lineno(), "Data is of format:", type(data))
            json_data = json.load(data)
    except Exception as e:
        if print_screen:
            print(lineno(), e)
        exit(1)
    return json_data


def get_cve_file(directory, download=False, print_screen=False):
    """

    :param print_screen:
    :param directory:
    :param download:
    :return:
    """
    import os
    from datetime import datetime
    from dateutil.relativedelta import relativedelta
    # region parameters
    # place to download full CVE file from
    url = "https://cve.mitre.org/data/downloads/"
    # filename to be downloaded or loaded from disk
    file_name = "allitems.xml"
    file_name_old = file_name + ".old"
    full_file = directory + file_name
    full_file_old = directory + file_name_old
    full_url = url + file_name
    # endregion parameters
    is_exist = os.path.exists(full_file)
    # region get file date
    if is_exist:
        mod_date_hm = datetime.fromtimestamp(os.path.getmtime(full_file)).date()  # - relativedelta(months=2)
    else:
        mod_date_hm = datetime.today().date()
    verify_data = datetime.today().date() - relativedelta(months=1)
    # endregion get file date
    # region decide if new download is needed
    if verify_data >= mod_date_hm or download or not is_exist:
        if print_screen:
            print(lineno(), "Downloading new CVE data file")
        if not os.path.exists(directory):
            os.makedirs(directory)
        url_response = get_url(url=full_url, method="get", print_screen=print_screen)
        url_response_text = url_response.text
        if is_exist:
            os.rename(full_file, full_file_old)
        save_file(file_name=full_file, data=url_response_text, print_screen=print_screen)
    else:
        if print_screen:
            print(lineno(), "Using existing CVE data file")
        url_response_text = open_file(full_file)
    # endregion decide if new download is needed
    file_type = file_name.split(".")[1]
    parsed_xml_data = pd_parse(data=url_response_text, data_type=file_type, print_screen=print_screen)
    return parsed_xml_data


def search_cve_data(data, cve_save_search, cve_save_directory, cve_name_filter=None, cve_description_filter=None, print_screen=False):
    """

    :param print_screen:
    :param data:
    :param cve_save_search:
    :param cve_save_directory:
    :param cve_name_filter:
    :param cve_description_filter:
    :return:
    """
    import os
    from datetime import datetime
    response = []
    if cve_name_filter is None:
        cve_name_filter = ""
    if cve_description_filter is None:
        cve_description_filter = ""
    for values in data.values:
        if cve_name_filter in values[0] and cve_description_filter in values[5]:
            value_resp = {
                data.keys()[0]: values[0],
                data.keys()[1]: values[1],
                data.keys()[2]: values[2],
                data.keys()[3]: values[3],
                data.keys()[4]: values[4],
                data.keys()[5]: values[5],
                data.keys()[6]: values[6],
                data.keys()[7]: values[7],
                data.keys()[8]: values[8]
            }
            response.append(value_resp)
    if cve_save_search:
        file_date_now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filtered_cve_list_json = json_pretty_print(json_data=response, indent=4)
        directory = str(cve_save_directory) + "/"
        if not os.path.exists(directory):
            os.makedirs(directory)
        file_name = directory + str(file_date_now) + "_filtered_cve_list.json"
        if print_screen:
            print(lineno(), file_name)
        save_file(file_name=file_name, data=filtered_cve_list_json, print_screen=print_screen)
    return response


def cve_data_lookup(directory, save_files, data, print_screen=False):
    """

    :param print_screen:
    :param directory:
    :param save_files:
    :param data:
    """
    import os
    # Place to download specific CVE from
    git_cve_url = "https://raw.githubusercontent.com/CVEProject/cvelist/master/"
    response_data_array = []

    for item in data:
        year = str(item['seq'].split("-")[0]) + "/"
        seq_series = item['seq'].split("-")[1][:-3] + "xxx/"
        file_name = item['name'] + ".json"
        cve_detail_file_url = git_cve_url + year + seq_series + file_name
        full_file_name = directory + year + seq_series + file_name
        if not os.path.exists(full_file_name):
            if print_screen:
                print(lineno(), "Filename", file_name, "Does not exist")
            cve_url_response = get_url(url=cve_detail_file_url, method="get", print_screen=print_screen)
            cve_url_response_json = cve_url_response.json()
            if save_files:
                if not os.path.exists(directory):
                    if print_screen:
                        print(lineno(), "Directory", directory, "Does not exist")
                    os.makedirs(str(directory))
                if not os.path.exists(directory + year):
                    if print_screen:
                        print(lineno(), "Sub Directory", directory + year, "Does not exist")
                    os.makedirs(str(directory + year))
                if not os.path.exists(directory + year + seq_series):
                    if print_screen:
                        print(lineno(), "Sub Directory", directory + year + seq_series, "Does not exist")
                    os.makedirs(str(directory + year + seq_series))
                save_file(file_name=full_file_name, data=json_pretty_print(json_data=cve_url_response_json, indent=4))
            response_data_array.append(cve_url_response_json)
    return response_data_array


def vuldb_com_cve_id_lookup(apikey, out_dir, cve_id, print_screen=False):
    """

    :param print_screen:
    :param apikey:
    :param out_dir:
    :param cve_id:
    :return:
    """
    import os
    from datetime import datetime
    from dateutil.relativedelta import relativedelta
    url = "https://vuldb.com/"
    cve_id_split = cve_id.split("-")
    file_name = cve_id + ".json"
    api_error_file_name = "api_error.json"
    base_dir = cve_id_split[1] + "/"
    sub_dir = cve_id_split[2][:-3] + "xxx/"
    full_dir = out_dir + "/" + base_dir + sub_dir
    full_file_path = full_dir + file_name
    full_api_error_file_path = out_dir + "/" + api_error_file_name
    # print(apikey, out_dir, cve_id, full_file_path)
    json_data = {}
    if not os.path.exists(full_file_path):
        if print_screen:
            print(lineno(), "File name:", file_name, "does not exist")
        if os.path.exists(full_api_error_file_path):
            error_mod_date_hm = datetime.fromtimestamp(
                os.path.getmtime(full_api_error_file_path)).date()  # - relativedelta(months=2)
            today = datetime.today().date()  # - relativedelta(days=3)
            # print(error_mod_date_hm, today)
            if error_mod_date_hm == today:
                if print_screen:
                    print(lineno(), "Error file exist and is today's date")
                exit(1)
            else:
                if print_screen:
                    print(lineno(), "Removing old error file and continuing")
                os.remove(full_api_error_file_path)
        # else:
        payload = {
            'apikey': apikey,
            'search': cve_id,
            'details': '1'
        }
        response = get_url(url=url, method="post", data=payload, print_screen=print_screen)
        json_data = response.json()
        if response.status_code != 200 or json_data['response']['status'] == "403":
            data = json_pretty_print(json_data=json_data, indent=4)
            save_file(file_name=full_api_error_file_path, data=data, print_screen=print_screen)
            if print_screen:
                print(lineno(), data)
            exit(1)
        else:
            data = json_pretty_print(json_data=json_data, indent=4)
            # print(lineno(), full_dir)
            # print(lineno(), full_file_path)
            # print(data)
            if not os.path.exists(full_dir):
                os.makedirs(full_dir)
            # full_dir = out_dir + "/" + base_dir + sub_dir
            save_file(file_name=full_file_path, data=data, print_screen=print_screen)
    else:
        if print_screen:
            print(lineno(), "File name:", file_name, "exists")
        json_data = load_json(open_file(full_file_path))
    return json_data


def cve_2_vulndb_lookup(array, apikey, out_dir, print_screen=False):
    """

    :param print_screen:
    :param array:
    :param apikey:
    :param out_dir:
    """
    from datetime import datetime
    vuldb_com_cve_id_array = {}
    x = 1
    for item in array:
        vuldb_com_cve_id_data = vuldb_com_cve_id_lookup(apikey=apikey, out_dir=out_dir, cve_id=item['name'],
                                                        print_screen=print_screen)
        vuldb_com_cve_id_array.update({'Search Record #' + str(x): vuldb_com_cve_id_data})
        x += 1
    vuldb_com_cve_id_array_json = json_pretty_print(json_data=vuldb_com_cve_id_array, indent=4)
    file_date_now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = out_dir + "/" + str(file_date_now) + "_vulndb_search_list.json"
    save_file(file_name=file_name, data=vuldb_com_cve_id_array_json, print_screen=print_screen)


def read_vulndb_output(data_dir, in_file_name, out_file_name, print_screen=False):
    """

    :param data_dir:
    :param in_file_name:
    :param out_file_name:
    :param print_screen:
    :return:
    """
    json_data = load_json(open_file(file_name=data_dir + "/" + in_file_name, print_screen=print_screen))
    response = []
    if print_screen:
        print(lineno(), "Output from VULNDB Search list")
    for item in json_data:
        results = json_data[item]['result'][0]
        countermeasure = results['countermeasure']
        cve_id = results['source']['cve']['id']
        advisory = results['advisory']
        source = results['source']
        # region future use
        try:
            versions = software['version']
        except Exception as e:
            component = e
        try:
            component = software['component']
        except Exception as e:
            component = e
        entry = results['entry']
        exploit = results['exploit']

        # endregion future use
        vulnerability = results['vulnerability']
        cvss3 = vulnerability['cvss3']

        try:
            cve_summary = source['cve']['summary']
        except Exception as e:
            cve_summary = e
        software = results['software']
        vendor = software['vendor']
        products = software['name']
        try:
            url = advisory['url']
        except Exception as e:
            url = e
        try:
            basescore = cvss3['meta']['basescore']
        except Exception as e:
            basescore = e

        value_resp = {
            'cve_id': cve_id,
            'basescore': basescore,
            'vendor': vendor,
            'products': products,
            'url': str(url),
            'cve_summary': str(cve_summary),
            'countermeasure': countermeasure
        }
        response.append(value_resp)
    data = json_pretty_print(json_data=response, indent=4)
    save_file(file_name=data_dir + "/" + out_file_name, data=data, print_screen=print_screen)
    return response
