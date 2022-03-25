#!/usr/bin/env bash
docker-compose down
./gradlew clean build && docker-compose build && ./test-em-all.bash start 
