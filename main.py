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
from functions import cmd_arguments, json_pretty_print, get_cve_file, search_cve_data
from functions import cve_2_vulndb_lookup, cve_data_lookup, read_vulndb_output, open_file


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


def main():
    """
    This is a sample on how to use the various functions in the functions.py script
    This provides 2 different options, where one option has 2 sub options

    Option 1:
    CVE Search, gets (or uses previous downloaded) allitems.xml from CVE.org,
    searches through that file with one or both of the 2 filters
        Sub-option 1:
        Save the above search entries to individual json Files per CVE record
        Sub-option 2:
        use the above search option to pull down individual CVE records from
        Vulndb.org database and save as individual json files
    Option 2:
    Use one of the saved searches from the Vulndb.org database and get
    specific useful information saved to a separate json file
    """
    import sys
    import textwrap
    args = cmd_arguments()
    if args['show_warranty']:
        print("Warranty")
    if args['show_conditions']:
        print("Conditions")

    if args['cve_search']:
        parsed_csv_xml_data = get_cve_file(directory=str(args['cve_file_directory']) + "/", download=args['cve_download'], print_screen=args['screen_output'])
        filtered_cve_list = search_cve_data(data=parsed_csv_xml_data, cve_save_search=args['cve_save_search'], cve_save_directory=args['cve_save_directory'], cve_name_filter=args['cve_name_filter'], cve_description_filter=args['cve_description_filter'], print_screen=args['screen_output'])
        if args['screen_output']:
            print(lineno(), "Number of entries in CVE search", len(filtered_cve_list))
        if args['cve_save_search']:
            if args['screen_output']:
                print(lineno(), "Save the search from cve.org to file")
            cve_data_lookup(directory=str(args['cve_file_directory']) + "/", save_files=args['cve_save_files'], data=filtered_cve_list, print_screen=args['screen_output'])
        if args['vulndb_cve_details']:
            if args['screen_output']:
                print(lineno(), "Get CVE Details from vulndb.com")
            cve_2_vulndb_lookup(array=filtered_cve_list, apikey=str(args['vulndb_api_key']), out_dir=str(args['vulndb_out_dir']), print_screen=args['screen_output'])
    if args['vulndb_in_file']:
        if args['screen_output']:
            print(lineno(), "Get basic info from saved Vulndb.com output")
        return_data_array = read_vulndb_output(data_dir=args['vulndb_out_dir'], in_file_name=str(args['vulndb_in_file']), out_file_name=str(args['vulndb_out_file']), print_screen=True)
        if args['screen_output']:
            print(lineno(), json_pretty_print(return_data_array))


if __name__ == '__main__':
    main()


