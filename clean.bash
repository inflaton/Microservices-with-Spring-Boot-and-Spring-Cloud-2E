#!/usr/bin/env bash
docker-compose down
docker rmi $(docker images -q)
