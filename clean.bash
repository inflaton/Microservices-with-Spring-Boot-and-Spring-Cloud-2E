#!/usr/bin/env bash
docker-compose down
docker rmi -f $(docker images "chapter*" -q)
