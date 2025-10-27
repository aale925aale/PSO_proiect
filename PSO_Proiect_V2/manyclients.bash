#!/bin/bash

N=50
URL="http://localhost:8080/"

for i in $(seq 1 $N); do
  curl -s -o /dev/null -w "%{http_code}\n" "$URL" &
done

wait
echo "Finished $N parallel requests"
