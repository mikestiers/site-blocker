# implement this without cheating (the easy, yet "wrong" way):
# iptables -A OUTPUT -p tcp --dport 80 -d reddit.com -j DROP
# add punishment time
# do not flush on start
# *find a way to read the comments
# safe way to set iptables off limits
# log and count how much time used
# redirect to a page when blocked using mangle

# OPTIONS
# a = apply rules
# d = delete rules
# m = monitor mode  # if monitoring, log traffic from blocked sites, analyze time spent
# t = set timeout
# h = threshold
# p = punishment  # requires monitoring, what is the punishment if threshold is met
# k = poison the network.  super aggressive mode.  maybe poison arp tables so all wifi devices are blocked and turn the system into a gateway


import os
import sys
import socket
import iptc
import time
import pdb

config_file = os.getenv("HOME") + '/site-blocker-rules.conf'
debug_file = os.getenv("HOME") + '/site-blocker-rules.log'

def readRules():
    config = open(config_file, 'r')
    for line in config.readlines():
        ip = socket.gethostbyname_ex(line.rstrip())  # returns a tuple.  gethostbyname() is just one address
        ip_list = ip[2] # split ip[2], which contains all addresses, into a list.  ip[1] contains the domain name
        if sys.argv[1] == "a":
            applyRule(line, ip_list)
        elif sys.argv[1] == "d":
            print "working on ", line
            deleteRule(line, ip_list)
        elif sys.argv[1] == "m":
            checkActivity()

def applyRule(line, ip_list):
    for ip in ip_list:
        t = time.time()
        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.dst = ip
        rule.target = rule.create_target("DROP")
        match = rule.create_match("comment")
        #match.comment = line.rstrip()
        match.comment = str(t) + "-" + line.rstrip()
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "OUTPUT")
        chain.insert_rule(rule)

def deleteRule(line, ip_list):
    debug = open(debug_file, 'a')
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "OUTPUT")

    rules_list = list()
    for rule in chain.rules:
        for match in rule.matches:
            if line.rstrip() in str(match.comment):
                rules_list.append(rule)

    position = 0
    rules_size = len(rules_list)

    #for r in reversed(rules_list):
    for r in chain.rules:
    #for r in rules_list:
        # fix this.  it makes the loop process the last rule first, but adding them to a list and reversing it does not work.  WHY
        for r in chain.rules:
            print r.dst
            print "nested loop: ", r
        #pdb.set_trace()
        #print "first loop", r
        #pdb.set_trace()
        # troubleshooting
        for match in r.matches:
            if line.rstrip() in str(match.comment):
                try:
                    #pdb.set_trace()
                    print "deleting ", r 
                    print "there are this many rules: ", len(rules_list)
                    chain.delete_rule(r)
                    position = position + 1
                except:
                    print "exception"
                    debug.write("Exception\n")
            else:
                print "no match"
    table.commit()

def checkActivity(line):
    # check logs to calculate how long someone has been browsing a blacklisted site
    print(time.clock())

    for line in sysloglines
        for ip in ip_list
            if ip matches destination
                log the time somehow

    # if the site has not been visited during the threshold, allow access again
    if last_time_logged > current time - reset_threshold
        deleteRule(line)
        restartCounter(line)

    if accumulated_time > threshold
        applyRule()

def restartCounter(line):
    restart the counter for the site

readRules()


######################check if rule exists before deleting it############################
######################loop through rules deleting until count is 0#######################

####the problem is when you delete an entry in iptables everything moves up one, but the index moves +1
####put the rules into a list, then delete them after finding comments that match up (does not work)
####or figure out how to step back one item in a list after deleting
####or repeat the command for the number of consecutive matches (does not work if they are not in order)
####or delete them backwards
####or setup a custom chain and then flush it (does not work because iptc cannot create new chains or jump links)
####getRuleCount() findRule(), deleteRule() until getRuleCount() returns 0

####make a function that reads on line of the rules, if it matches, do something
####if it does not match, return false
####loop as many times as there are rules
####this way the list of rules is always fresh


#the easiest cheater way of doing this is to make a custom chain, then kill the chain when time expires

