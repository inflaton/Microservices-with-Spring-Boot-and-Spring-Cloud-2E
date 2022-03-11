#!/usr/bin/env bash
./gradlew clean build && docker-compose build && ./test-em-all.bash start stop