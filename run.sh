#!/bin/bash
docker compose up -d
sleep 3
docker exec -d  ueransim bash -c  "./nr-ue -c config/uecfg.yaml &> ./uelog.txt"
sleep 2
docker exec ueransim cat ./uelog.txt > ./logs/uelog.txt
docker logs amf &> ./logs/amflog.txt
docker compose down
echo "========================================LOG UE==============================="
cat ./logs/uelog.txt
echo "========================================LOG AMF=============================="
cat ./logs/amflog.txt
