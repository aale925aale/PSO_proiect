#!/bin/bash

#Script de test pentru simulare a 50 de clienti care vor sa se conecteze la server. 
#In terminalul CLient se va afisa codul de finalizare al cererii (200 = SUCCES)
N=50
URL="http://localhost:8080/"

for i in $(seq 1 $N); do
  curl -s -o /dev/null -w "%{http_code}\n" "$URL" &
done

wait
echo "Finished $N parallel requests"
