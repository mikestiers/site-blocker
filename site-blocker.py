# implement this without cheating (the easy, yet "wrong" way):
# iptables -A OUTPUT -p tcp --dport 80 -d reddit.com -j DROP
# add punishment time
# do not flush on start
# find a way to read the comments

import os
import socket
import iptc
import time

config_file = os.getenv("HOME") + '/site-blocker-rules.conf'
debug_file = os.getenv("HOME") + '/site-blocker-rules.log'

def readRules():
    config = open(config_file, 'r')
    for line in config.readlines():
        ip = socket.gethostbyname_ex(line.rstrip())  # returns a tuple.  gethostbyname() is just one address
        ip_list = ip[2] # split ip[2], which contains all addresses, into a list.  ip[1] contains the domain name
        #applyRule(line, ip_list)
        deleteRule(line, ip_list)
        
    
def applyRule(line, ip_list):
    for ip in ip_list:
        t = time.time()
        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.dst = ip
        rule.target = rule.create_target("DROP")
        match = rule.create_match("comment")
        match.comment = str(t) + "-" + line.rstrip()
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "OUTPUT")
        chain.insert_rule(rule)

def deleteRule(line, ip_list):
    debug = open(debug_file, 'a')
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "OUTPUT")
    # change this from ip list to if line in chain.rule[x].matches[x].comment
#    for ip in ip_list:
#        for rule in chain.rules:
#            print(ip)
#            print rule.matches
#            if (ip in rule.dst):
#                try:
#                    chain.delete_rule(rule)
#                    debug.write("Deleting rule: " + str(rule) + "\n")
#                    debug.write("IP: " + str(ip) + "\n")
#                    debug.write("IP List: " + str(ip_list) + "\n")
#                except:
#                    print "except"
#                    debug.write("Exception: " + str(rule) + "\n")
#                    debug.write("IP: " + str(ip) + "\n")
#                    debug.write("IP List: " + str(ip_list) + "\n")
#                else:
#                    print "no match" + ip
#                    debug.write("No match: " + str(rule) + "\n")
#                    debug.write("IP: " + str(ip) + "\n")
#                    debug.write("IP List: " + str(ip_list) + "\n")

    rules_list = list()
    for rule in chain.rules:
        for match in rule.matches:
            if line.rstrip() in str(match.comment):
                rules_list.append(rule)
#                try:
#                    chain.delete_rule(rule)
#                except:
#                    print "except"
#                else:
#                    print "no match " + line.rstrip()

    position = 0
    rules_size = len(rules_list)

    for r in rules_list:
        try:
            chain.delete_rule(rules_list[0]) # used to be just "r"
            debug.write("Position AD: " + str(position) + "\n")
            debug.write("Rule AD: " + str(r) + "\n")
            debug.write("Rule dst AD: " + str(r.dst) + "\n")
            debug.write("Rules List AD: " + str(r) + "\n")
        except:
            print "exception"
            debug.write("Exception\n")
        else:
            print "else"
            debug.write("Else\n")
        print "Rules: ", len(rules_list)

def checkActivity(line):
    # check logs to calculate how long someone has been browsing a blacklisted site
    print(time.clock())

readRules()


####the problem is when you delete an entry in iptables everything moves up one, but the index moves +1
####put the rules into a list, then delete them after finding comments that match up (does not work)
####or figure out how to step back one item in a list after deleting
####or repeat the command for the number of consecutive matches (does not work if they are not in order)
####or delete them backwards
####or setup a custom chain and then flush it (does not work because iptc cannot create new chains or jump links)
####getRuleCount() findRule(), deleteRule() until getRuleCount() returns 0



