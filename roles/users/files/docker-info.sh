#!/bin/bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Mounts}}" --no-trunc
