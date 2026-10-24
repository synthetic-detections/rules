#!/usr/bin/env python3
# benign: legitimate cloud credential helper that reads ~/.aws/credentials
import os, json

def get_aws_profile(profile="default"):
    cred_file = os.path.expanduser("~/.aws/credentials")
    if not os.path.exists(cred_file):
        return None
    with open(cred_file) as f:
        return f.read()

if __name__ == "__main__":
    print(get_aws_profile())
