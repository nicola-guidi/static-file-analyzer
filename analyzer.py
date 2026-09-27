import argparse
import hashlib
import os
import sys
import datetime

# CLI argument parser
parser = argparse.ArgumentParser()
parser.add_argument("-s", "--sample", help="input file", required=True)
args = parser.parse_args()

# Metadata parser
def file_metadata(sample):
    metadata = {
        "name": os.path.basename(sample),
        "size": os.path.getsize(sample),
        "path": os.path.abspath(sample),
        "extension": os.path.splitext(sample)[1],
        "modified": os.path.getmtime(sample),
        "accessed": os.path.getatime(sample)
    }
    return metadata

# Reads the first 8 bytes of a file and returns them to data
def magic_bytes(sample):
    with open(sample, "rb") as f:
        data = f.read(8)
        return data

# Signatures dictionary
signatures = {b"MZ": "Windows PE",
              b"%PDF": "PDF Document",
              b"PK": "ZIP Archive",
              b"\x89PNG": "PNG Image",
              b"\xFF\xD8\xFF": "JPEG Image",
              b"GIF87a": "GIF Image",
              b"GIF89a": "GIF Image",
              }

# Checks dictionary keys against first_bytes
def signature_validation(first_bytes):
    for key in signatures:
        if first_bytes[:len(key)] == key:
            return signatures[key]
    return "Unknown"

# Hashing function
def hashing(sample):
    with open(sample, "rb") as f:
        sample_bytes = f.read()
        md5 = hashlib.md5(sample_bytes).hexdigest()
        sha1 = hashlib.sha1(sample_bytes).hexdigest()
        sha256 = hashlib.sha256(sample_bytes).hexdigest()
        hashes = {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        }
        return hashes

# Extract all strings
def extract_strings(sample):
    strings = []
    current_string = []
    with open(sample, "rb") as f:
        sample_bytes = f.read()
        for sample_byte in sample_bytes:
            if 32 <= sample_byte <= 126:
                current_string.append(sample_byte)
            else:
                if current_string:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = []
        if current_string:
            if len(current_string) >= 4:
                strings.append(current_string)
    return strings

# Saves all strings into a text file
def save_strings(unique_strings):
    with open("strings.txt", "w") as f:
        for unique_string in unique_strings:
            f.write(unique_string + "\n")

# Filters urls found in strings
def find_urls(unique_strings):
    urls = []
    for unique_string in unique_strings:
        if unique_string[:7] == "http://" or unique_string[:8] == "https://":
            urls.append(unique_string)
    return urls

# Filters ips found in strings
def find_ips(unique_strings):
    ips = []

    for unique_string in unique_strings:
        try:
            valid_ip = True
            octets = unique_string.split(".")
            if len(octets) == 4:
                for octet in octets:
                    if len(octet) == 0 or len(octet) > 3 or int(octet) not in range(256):
                        valid_ip = False
                if valid_ip:
                    ips.append(unique_string)
        except ValueError:
            continue
    return ips

# Top level domains
tlds = [
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "io",
    "it",
    "de",
    "fr",
    "uk",
    "app"
]

# Filters domains found in strings
def find_domains(unique_strings):
    domains = []
    for unique_string in unique_strings:
        unique_domain = unique_string.split("/")
        if "." in unique_domain[0]:
            unique_domain = unique_domain[0].split(".")
            if unique_domain[0] and unique_domain[-1] in tlds:
                domains.append(unique_string)
    return domains

# File extensions
file_extensions = [
    "exe",
    "dll",
    "elf",
    "xls",
    "doc"
]
# Filters files found in strings
def find_files(unique_strings, domains, urls):
    files = []
    for unique_string in unique_strings:
        unique_file = unique_string.split(".")
        if "." in unique_string and unique_file[-1] in file_extensions and unique_string not in urls and unique_string not in domains:
            files.append(unique_string)
    return files

# Validates if sample is a file
def main():
    print("")
    print("========================================")
    print("           FILE ANALYSIS")
    print("========================================")
    print("")
    try:
        if os.path.isfile(args.sample):
            metadata = file_metadata(args.sample)
            # Metadata function calls
            print("[METADATA]")
            print(f"File name: {metadata['name']}")
            print(f"File size: {metadata['size']}")
            print(f"File location: {metadata['path']}")
            print(f"File extension: {metadata['extension']}")
            date_modified = datetime.datetime.fromtimestamp(metadata['modified']).strftime("%Y-%m-%d %H:%M:%S")
            print(f"File modified: {date_modified}")
            date_accessed = datetime.datetime.fromtimestamp(metadata['accessed']).strftime("%Y-%m-%d %H:%M:%S")
            print(f"File accessed: {date_accessed}")
            first_bytes = magic_bytes(args.sample)
            result = signature_validation(first_bytes)

            # File type function call
            print("")
            print("[FILE TYPE]")
            print(f"File type (magic bytes validation): {result}")
            hashes = hashing(args.sample)

            # Hashing function call
            print("")
            print("[HASHES]")
            print(f"MD5:     {hashes['md5']}")
            print(f"SHA1:    {hashes['sha1']}")
            print(f"SHA256:  {hashes['sha256']}")
            found_strings = extract_strings(args.sample)
            unique_strings = []
            for string in found_strings:
                decoded_strings = bytes(string).decode("ascii")
                if decoded_strings not in unique_strings:
                    unique_strings.append(decoded_strings)
            save_strings(unique_strings)

            # URLs function call
            print("")
            print("[URLS]")
            found_urls = find_urls(unique_strings)
            for url in found_urls:
                print(url)

            # IPs function call
            print("")
            print("[IP ADDRESSES]")
            found_ips = find_ips(unique_strings)
            for ip in found_ips:
                print(ip)

            # Domains function calls
            print("")
            print("[DOMAINS / DOMAIN PATHS]")
            found_domains = find_domains(unique_strings)
            for domain in found_domains:
                print(domain)

            # Files function call
            print("")
            print("[FILES]")
            found_files = find_files(unique_strings, found_domains, found_urls)
            for file in found_files:
                print(file)
            print("")
            print("===========================================================")
            print("   All other strings have been saved in ./strings.txt")
            print("===========================================================")

        else:
            print("Sample is not a file")


    # Permission error
    except PermissionError:
        print("Permission Error")
        sys.exit()

    # CTRL+C graceful exit
    except KeyboardInterrupt:
        print("Analysis interrupted by user")
        sys.exit()

# Main function call
if __name__ == "__main__":
    main()




