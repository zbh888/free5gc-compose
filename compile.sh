#!/bin/bash
make amf
docker compose -f docker-compose-build.yaml build free5gc-amf
docker rmi $(docker images -f "dangling=true" -q)
