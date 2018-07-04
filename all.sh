#!/bin/bash

echo "Connection attempt seen, no reply"
cat conn.log | bro-cut -d | awk '$12 == "S0" {print $5}' | sort | uniq -c | sort -rn
echo ""

echo "Connection established, not terminated (0 byte counts)"
cat conn.log | bro-cut -d | awk '$12 == "S1" {print $5}' | sort | uniq -c | sort -rn
echo ""

echo "Normal establish & termination (>0 byte counts)"
cat conn.log | bro-cut -d | awk '$12 == "SF" {print $5}' | sort | uniq -c | sort -rn
echo ""

echo "Orig sent SYN then FIN; no Resp SYN-ACK (“half-open”)"
cat conn.log | bro-cut -d | awk '$12 == "SH" {print $5}' | sort | uniq -c | sort -rn
echo ""

echo "All successfull established ssl connections."
cat ssl.log | bro-cut -d | awk '$14 == "T" {print $10}' | sort | uniq -c | sort -rn
echo ""

echo "All NOT successfull established ssl connections."
cat ssl.log | bro-cut -d | awk '$14 == "F" {print $10}' | sort | uniq -c | sort -rn
echo ""

echo "Top off all used methods"
cat http.log | bro-cut -d | awk '{print $8}' | sort | uniq -c | sort -rn
echo ""

echo "Top off all used methods with hostname"
cat http.log | bro-cut -d | awk '{print $8 "\t" $9}' | sort | uniq -c | sort -rn
echo ""

# No referrer domain is accessed directly of from a search enigne.
echo "Top of all host that have been directly accessed. (Without a referrer.)"
cat http.log | bro-cut -d | awk '$11 == "-" {print $8 "\t" $9}' | sort | uniq -c | sort -rn
echo ""

echo "Top of all host that have been indirectly accessed. (With referrer.)"
cat http.log | bro-cut -d | awk '$11 != "-" {print $8 "\t" $9}' | sort | uniq -c | sort -rn
echo ""

echo "SSH successfull authentication"
echo -e "id.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tclient\tserver"
 cat ssh.log | bro-cut -d id.orig_h id.orig_p id.resp_h id.resp_p version auth_success client server | awk 'BEGIN {FS="\t"}; $6 == "T" {print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $7 "\t" $8}'
echo ""

echo "SSH NOT successfull authentication"
echo -e "id.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tclient\tserver"
 cat ssh.log | bro-cut -d id.orig_h id.orig_p id.resp_h id.resp_p version auth_success client server | awk 'BEGIN {FS="\t"}; $6 == "F" {print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $7 "\t" $8}'
echo ""
