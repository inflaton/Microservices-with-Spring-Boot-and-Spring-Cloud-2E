#!/usr/bin/env bash
docker-compose down
docker rmi -f $(docker images "chapter*" -q)
docker run --privileged --pid=host docker/desktop-reclaim-space
docker system prune -f
