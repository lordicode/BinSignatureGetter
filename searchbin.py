#!/usr/bin/env python3
"""
Pattern: searchbin.py -p HexPattern [FILE [FILE...]]

Example: searchbin.py -p "F2F1FFCD" userdata.bin
Explanation: Searches for the hexidecimal pattern "CCDDFF" in myfile.bin.

+No compiling, fast, small file, search file of unlimited size, all operating systems
+Can be adjusted for other Hex signatures and offsets to be extracted after signature
+Minimum Py 3.+
+keywords binary grep search/seek/find/write is decently fast, 7 Gb < 6 seconds
+Can be run via CMD with supplied arguments or with the powershell script attached
"""

from __future__ import unicode_literals

import logging
import os
import re
import signal
import sys
import time

log_out = os.path.dirname(os.path.realpath(__file__)) + "\\search_bin.log"
logging.basicConfig(filename=log_out, level=logging.DEBUG, format="{asctime} {message}", style='{')
#tried making the logging to file from exe work, but I couldn't
#logging if the script is run as .py works
logging.getLogger().addHandler(logging.StreamHandler(logging.basicConfig(filename=log_out, level=logging.DEBUG, format="{asctime} {message}", style='{')))
try:  # Python 3 check.
    STDIN = sys.stdin.buffer
except SystemExit:
    logging.error("Wrong Python version!")
    quit()

# global variable displayed on command line call
CONTACT = """\nBy @lordicode\n"""


def _exit_error(code, err=None):
    """
    Error information.
    """
    error_codes = {
        "Xpatterns":
            "Cannot search for multiple patterns. '-p'",
        "0patterns":
            "No pattern to search for was supplied. '-p' Expected",
        "openfile":
            "Failed opening file.",
        "read":
            "Failed reading from file.",
        "unknown":
            "unknown error"
        #@TODO: Logging to file when exe run doesn't work, make more error calls, make program exit gracefully
    }

    import traceback
    sys.stderr.write(traceback.format_exc() + "\n")
    if err:
        logging.error("Script is run without parameters/incorrect parameters.\n"
                      "Please review the instructions sent with the script.\nFor any questions contact: %s\n" % CONTACT)
        sys.stderr.write(
            "Script is run without parameters/incorrect parameters.\n"
            "Please review the instructions sent with the script.\nFor any questions contact: %s\n" % CONTACT)
        sys.stderr.write("%s\n" % str(err))
    sys.stderr.write("Error <%s>: %s\n\n" % (code, error_codes[code]))
    if __name__ == "__main__":
        sys.exit(128)  # Exit under normal operation.
    raise


def get_args():
    """
    Parse all arguments from the command line using ArgumentParser.
    Returns an args object with attributes representing all arguments.
    """
    from argparse import ArgumentParser
    description = """
    An argument -p is required. The -p argument accepts a 
    hexidecimal pattern string and allows for missing characters, 
    such as 'FF??FF'. Reported finds are 0-based offset.
    """
    logging.info("""
    An argument -p is required. The -p argument accepts a 
    hexidecimal pattern string and allows for missing characters, 
    such as 'FF??FF'. Reported finds are 0-based offset.
    """)
    p = ArgumentParser(description=description)

    p.add_argument('-f', '--file', type=str,
                   metavar='FILE', dest='fpattern',
                   help='file to read search pattern from')
    p.add_argument('-p', '--pattern', type=str,
                   metavar='PATTERN', dest='ppattern',
                   help='a hexidecimal pattern to search for')
    #for future possible expansion of functionality
    try:
        p.add_argument('-b', '--buffer-size', type=int,
                       metavar='NUM', dest='bsize',
                       help='read buffer size (in bytes). 8MB default')
        p.add_argument('-s', '--start', type=int,
                       metavar='NUM', dest='start',
                       help='starting position in file to begin searching, as bytes')
        p.add_argument('-e', '--end', type=int,
                       metavar='NUM', dest='end',
                       help='end search at this position, measuring from beginning of file')
        p.add_argument('-m', '--max-matches', type=int,
                       metavar='NUM', dest='max_matches',
                       help='maximum number of matches to find (0=infinite)')
    except ArgumentParser:
        logging.error("Argument parser error")

    p.add_argument('-l', '--log', type=str,
                   metavar='FILE', dest='log',
                   help='write matched offsets to FILE, instead of standard output')
    p.add_argument(type=str,
                   metavar='FILE', dest='fsearch', nargs='*',
                   help='files to search within')
    p.add_argument('-v', '--verbose',
                   dest='verbose', action='store_true',
                   help='verbose, output the number of bytes searched after each buffer read')
    return p.parse_args()


def hex_to_pattern(hex_pt):
    """ Converts a hex string into a pattern. """
    pattern = hex_pt
    if hex_pt[:2] == "0x":  # Remove "0x" from start if it exists.
        pattern = hex_pt[2:]
    try:
        ret = [p for p in pattern.split("??")]
        try:  # Python 3.
            return [bytes.fromhex(p) for p in ret]
        except AttributeError:
            logging.error("Could not be converted")
    except(TypeError, ValueError):
        e = sys.exc_info()[1]
        _exit_error("decode", e)
        logging.error(_exit_error("decode", e))


# We will be keeping the parsed args object and editing its attributes!
def verify_args(ar):
    """
    Verify that all the parsed args are correct and work well together.
    Returns the modified args object.
    """

    # Make sure that exactly 1 pattern argument was given.
    all_patterns = list(filter(None, [ar.ppattern]))
    if len(all_patterns) > 1:
        _exit_error("Xpatterns")
        logging.error(_exit_error("Xpatterns"))
    if len(all_patterns) == 0:
        try:
            logging.error(_exit_error("0patterns"))
            _exit_error("0patterns")
        except ValueError:
            logging.error(ValueError)
            quit()

    # Create a new variable ar.pattern, and fill it with
    # pattern -p
    ar.pattern = hex_to_pattern(ar.ppattern)

    # Convert all number args from strings into integers.
    try:
        for attr in ["bsize", "max_matches", "start", "end"]:
            if getattr(ar, attr):
                setattr(ar, attr, int(getattr(ar, attr)))
    except ValueError:
        e = sys.exc_info()[1]
        _exit_error("sizes", err=e)

    # Buffer size must be at least double maximum pattern size.
    if ar.bsize:
        if ar.bsize < len("?".join(ar.pattern)) * 2:
            _exit_error("bsize", len("?".join(ar.pattern)) * 2)
            logging.error(_exit_error("bsize", len("?".join(ar.pattern)) * 2))
    else:
        ar.bsize = len(b"".join(ar.pattern)) * 2
        ar.bsize = max(ar.bsize, 2 ** 23)  # If bsize is < default, set to default.

    # Set start and end values to 0 if not set.
    ar.start = ar.start or 0
    ar.end = ar.end or 0
    # End must be after start.  :)
    if ar.end and ar.start >= ar.end:
        _exit_error("startend")
        logging.error(_exit_error("startend"))
    return ar


def search(ar, fh):
    """
    This function is simply a wrapper to forward needed variables in a way
    to make them all local variables. Accessing local variables is faster than
    accessing object.attribute variables.
    Returns nothing.
    """
    try:
        _search_loop(ar.start, ar.end, ar.bsize, ar.pattern, fh.name,
                     fh.read, fh.seek)
    except RuntimeError:
        quit()


def _search_loop(start, end, bsize, pattern, fh_name, fh_read, fh_seek):
    with open(fh_name, 'rb') as first_file, open(
            "output.bin", "wb") as second_file:
        """
        Search function.
        Returns nothing.
        """
        len_pattern = len(b"?".join(pattern))  # Byte length of pattern.
        read_size = bsize - len_pattern  # Amount to read each loop.

        # Python native regex search engine is insanely fast. This converts the pattern into regex.
        pattern = [re.escape(p) for p in pattern]
        pattern = b".".join(pattern)
        # Grab regex search function directly to speed up function calls.
        regex_search = re.compile(pattern, re.DOTALL + re.MULTILINE).search

        offset = start or 0
        # Set start reading position in file.
        count = 0
        try:
            if offset:
                fh_seek(offset)
        except IOError:
            e = sys.exc_info()[1]
            _exit_error("read", fh_name, e)
            logging.error(_exit_error("read", fh_name))

        try:
            buffer = fh_read(len_pattern + read_size)  # Get initial buffer amount.
            if count == 0:
                logging.debug(f"Buffer size: %d" % sys.getsizeof(buffer))
            match = regex_search(buffer)  # Search for a match in the buffer.
            # Set match to -1 if no match, else set it to the match position.
            match = -1 if match is None else match.start()

            while True:  # Begin main loop for searching through a file.

                if match == -1:  # No match.
                    offset += read_size
                    # If end exists and we are beyond end, finish search.
                    if end and offset > end:
                        return
                    buffer = buffer[read_size:]  # Erase front portion of buffer.
                    buffer += fh_read(read_size)  # Read more into the buffer.
                    match = regex_search(buffer)  # Search for next match in the buffer.
                    # If there is no match set match to -1, else the matching position.
                    match = -1 if match is None else match.start()
                else:  # Else- there was a match.
                    # If end exists and we are beyond end, finish search.
                    if match == -1 and offset + match > end:
                        return

                    #Get matched offset.
                    find_offset = offset + match
                    #move to the offset with a match
                    start_on = first_file.seek(find_offset)
                    #calculate offset + N bytes. 0x100 is just for illustratory purposes
                    end_on = start_on + 0x100
                    stuff = first_file.read(end_on - start_on)
                    #write to file all bytes from offset to N after it
                    second_file.write(stuff)
                    try:
                        sys.stdout.write("Match at offset: %14d %12X in  %s\n" % (
                            find_offset, find_offset, fh_name))
                        logging.info(
                            f"Match at offset: %14d %12X in  %s\nWriting to {second_file} from offset {start_on} to "
                            f"offset {end_on}" % (
                                find_offset, find_offset, fh_name))
                    except IOError:
                        logging.info("Match at offset: %14d %12X in  %s\n" % (
                            find_offset, find_offset, fh_name))
                        logging.info(f"Writing to {second_file} from offset {start_on} to offset {end_on}")
                    # Search for next match in the buffer.
                    match = regex_search(buffer, match + 1)
                    match = -1 if match is None else match.start()

                if len(buffer) <= len_pattern:  # If finished reading input then end.
                    sys.stdout.write("Finished iterating the file.")
                    logging.info("Finished iterating the file'")
                    return
        # Main loop closes here.

        except IOError:
            e = sys.exc_info()[1]
            _exit_error("read", fh_name, e)
            logging.error(_exit_error("read", fh_name))


def main():
    start_time = time.time()
    # dt = datetime.datetime.fromtimestamp(start_time)
    logging.info("Execution started\n")
    args = get_args()  # Get commandline arguments.
    # iterates through the Namespace object of arguments to print them to logs
    for k, v in args.__dict__.items():
        if args.__dict__[k] is not None:
            logging.debug(f"Argument {k} : {v} is passed to the script")
    args = verify_args(args)  # Check arguments for sanity, and edit them a bit.
    if args.fsearch:  # If filenames were given on the commandline, process them.
        while args.fsearch:  # List of files to search inside.
            try:  # Open a filehandler for the filename.
                filehandler = open(args.fsearch[0], "rb")
                if not filehandler:
                    filehandler = os.path.abspath(os.path.join())
                logging.debug(f"{filehandler} opened and is being searched")
                # get size just for statistics
                getSize = os.stat(args.fsearch[0]).st_size
                logging.info(f"Userdata.bin is {getSize} bytes long.")
                # start the search
                search(args, filehandler)
                # close the file
                filehandler.close()
                logging.debug(f"{filehandler} is closed")
            except IOError:
                e = sys.exc_info()[1]
                _exit_error("openfile", args.fsearch[0], e)
                logging.error(f"Error:{_exit_error('openfile', args.fsearch[0])}")

            args.fsearch.pop(0)  # Remove file after search
    else:
        logging.error("fsearch failed")
        quit()
    logging.info("Execution finished")
    sys.stdout.write("Execution finished\n")
    time_took = time.time() - start_time
    logging.info("Execution finished in %s" % time_took)
    sys.stdout.write("Finished in %s \n" % time_took)
    import hashlib
    filename = "output.bin"
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        # this a future-proof feature allowing to calculate hashes of files of large size
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        sha_hash = sha256_hash.hexdigest()
        logging.info(f"SHA256 of the output.bin is {sha_hash}\n\n\n\n")
    sys.exit(0)


# executes the files if run directly and not imported while running another script
if __name__ == "__main__":
    # This allows the program to exit quickly when pressing ctrl+c. Dumps the code from memory immediately.
    # https://docs.python.org/3/library/signal.html
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()

""""-------------------------------------@lordicode--------------------------------------------------"""
