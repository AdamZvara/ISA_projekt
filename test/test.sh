#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD=$(tput bold)

declare -i PASSEDCNT=0
declare -i FAILEDCNT=0
declare -i ALLCNT=0

# echo -e "${BLUE}Running options tests${NC}"
# while read -r CMD; do
#     ALLCNT+=1
#     read -r RESULT
#     ERROR=$($CMD 2>&1 >/dev/null)
#     echo -n "$CMD "
#     if [ "$ERROR" = "$RESULT" ]; then
#         echo -e "${GREEN}Passed${NC}"
#         PASSEDCNT+=1
#     else
#         echo -e "${RED}Failed${NC}"
#         FAILEDCNT+=1
#     fi
# done < cases

echo ""
echo -e "${BLUE}Running complex tests${NC}"

for FILE in `ls src`; do
    ALLCNT+=1
    echo -e -n "${FILE}: "
    nfcapd -n "$FILE,127.0.0.1,out" 2> /dev/null &
    PID=$!

    .././flow -f "src/$FILE" -c localhost:9995

    kill $PID

    nfdump -r `ls out/nfcapd*` -q -O tstart -o 'fmt:%sa:%sp %da:%dp %pr %pkt %byt %tos' > "out/${FILE}_out"
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

echo " "
echo -e "Passed ${GREEN}${BOLD}$PASSEDCNT${NC} out of ${BLUE}${BOLD}$ALLCNT${NC} tests"