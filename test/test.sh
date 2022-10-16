#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD=$(tput bold)

declare -i PASSEDCNT=0
declare -i FAILEDCNT=0
declare -i ALLCNT=0

echo -e "${BLUE}Running options tests${NC}"
while read -r CMD; do
    ALLCNT+=1
    read -r RESULT
    ERROR=$($CMD 2>&1 >/dev/null)
    echo -n "$CMD "
    if [ "$ERROR" = "$RESULT" ]; then
        echo -e "${GREEN}Passed${NC}"
        PASSEDCNT+=1
    else
        echo -e "${RED}Failed${NC}"
        FAILEDCNT+=1
    fi
done < cases

echo ""
echo -e "${BLUE}Running complex tests${NC}"

rm -rf out/nfcapd*

for FILE in `ls src`; do
    ALLCNT+=1
    echo -e -n "${FILE}: "
    nfcapd -n "$FILE,127.0.0.1,out" 2> /dev/null &
    PID=$!
    sleep 0.3

    .././flow -f "src/$FILE" -c 127.0.0.1:9995

    kill $PID

    nfdump -r `ls out/nfcapd*` -q -o 'fmt:%sa:%sp %da:%dp %pr %pkt %byt %tos' | sort > "out/${FILE}_out"
    if [ $? -ne 0 ]; then
        echo -e "${RED}${BOLD}TESTS FAILED, RERUN"
        exit 1
    fi



    diff -w  --changed-group-format='%<' --unchanged-group-format='' out/${FILE}_out out/${FILE%.*}
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Passed${NC}"
        PASSEDCNT+=1
    else
        echo -e "${RED}Failed${NC}"
        FAILEDCNT+=1
    fi

    rm -rf out/nfcapd*
done

echo ""
echo -e "${BLUE}Running flow cache capacity tests${NC}"

FILES=("mixed.pcap" "tcp.pcap")
for FILE in ${FILES[@]}; do
    ALLCNT+=1
    echo -e -n "${FILE}: "
    nfcapd -n "$FILE,127.0.0.1,out" 2> /dev/null &
    PID=$!
    sleep 0.3

    .././flow -f "src/$FILE" -c 127.0.0.1:9995 -m 5

    kill $PID

    nfdump -r `ls out/nfcapd*` -q -o 'fmt:%sa:%sp %da:%dp %pr %pkt %byt %tos' | sort > "out/${FILE}_fcache"
    if [ $? -ne 0 ]; then
        echo -e "${RED}${BOLD}TESTS FAILED, RERUN"
        exit 1
    fi

    diff -w  --changed-group-format='%<' --unchanged-group-format='' out/${FILE}_fcache out/${FILE%.*}_fcache
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Passed${NC}"
        PASSEDCNT+=1
    else
        echo -e "${RED}Failed${NC}"
        FAILEDCNT+=1
    fi

    rm -rf out/nfcapd*
done

echo ""
echo -e "${BLUE}Running active/inactive timer tests${NC}"
for FILE in ${FILES[@]}; do
    ALLCNT+=1
    echo -e -n "${FILE}: "
    nfcapd -n "$FILE,127.0.0.1,out" 2> /dev/null &
    PID=$!
    sleep 0.3

    .././flow -f "src/$FILE" -c 127.0.0.1:9995 -i 5 -a 30

    kill $PID

    nfdump -r `ls out/nfcapd*` -q -o 'fmt:%sa:%sp %da:%dp %pr %pkt %byt %tos' | sort > "out/${FILE}_timers"
    if [ $? -ne 0 ]; then
        echo -e "${RED}${BOLD}TESTS FAILED, RERUN"
        exit 1
    fi

    diff -w  --changed-group-format='%<' --unchanged-group-format='' out/${FILE}_timers out/${FILE%.*}_timers
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Passed${NC}"
        PASSEDCNT+=1
    else
        echo -e "${RED}Failed${NC}"
        FAILEDCNT+=1
    fi

    rm -rf out/nfcapd*
done

echo " "
echo -e "Passed ${GREEN}${BOLD}$PASSEDCNT${NC} out of ${BLUE}${BOLD}$ALLCNT${NC} tests"