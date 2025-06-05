#!/bin/bash

search_string="/openmemory/api/.venv/bin/python"

pid=$(ps aux | grep "$search_string" | grep -v grep | awk '{print $2}')

if [ -n "$pid" ]; then
    kill -9 $pid
    echo "프로세스 $pid 종료 완료"
else
    echo "해당하는 프로세스가 없습니다."
fi



