#!/usr/bin/env python

# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


from panos import firewall
from panos.policies import Rulebase, SecurityRule
import os

password = os.environ['PWRD']

def find_log_start(fw):
    rulebase = fw.add(Rulebase())
    print(rulebase)
    rules = SecurityRule.refreshall(rulebase)
    # print(rules)
    rule_log_start = []
    for rule in rules:
        if rule.log_start == True:
            rule_log_start.append(rule.name)
        else:
            pass
    return rule_log_start



def create_device(dev):
    frwl = firewall.Firewall(dev[0], api_username = dev[1], api_password = dev[2])
    print(frwl.refresh_system_info())
    return frwl


def main():
    palo = create_device(["1.1.1.1", "admin", password])
    print(find_log_start(palo))


if __name__ == "__main__":
    main()