#!/bin/bash
#
# dockerpsns - proof of concept for a "docker ps --namespaces".
#
# USAGE: ./dockerpsns.sh
#
# This lists containers, their init PIDs, and namespace IDs. If container
# namespaces equal the host namespace, they are colored red (this can be
# disabled by setting color=0 below).
#
# Copyright 2017 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 10-Apr-2017   Brendan Gregg   Created this.

namespaces="cgroup ipc mnt net pid user uts"
color=1
declare -A hostns

printf "%-14s %-20s %6s %-16s" "CONTAINER" "NAME" "PID" "PATH"
for n in $namespaces; do
    printf " %-10s" $(echo $n | tr a-z A-Z)
done
echo

# print host details
pid=1
read name < /proc/$pid/comm
printf "%-14s %-20.20s %6d %-16.16s" "host" $(hostname) $pid $name
for n in $namespaces; do
    id=$(stat --format="%N" /proc/$pid/ns/$n)
    id=${id#*[}
    id=${id%]*}
    hostns[$n]=$id
    printf " %-10s" "$id"
done
echo

# print containers
for UUID in $(docker ps -q); do
    # docker info:
    pid=$(docker inspect -f '{{.State.Pid}}' $UUID)
    name=$(docker inspect -f '{{.Name}}' $UUID)
    path=$(docker inspect -f '{{.Path}}' $UUID)
    name=${name#/}
    printf "%-14s %-20.20s %6d %-16.16s" $UUID $name $pid $path

    # namespace info:
    for n in $namespaces; do
        id=$(stat --format="%N" /proc/$pid/ns/$n)
        id=${id#*[}
        id=${id%]*}
        docolor=0
        if (( color )); then
            [[ "${hostns[$n]}" == "$id" ]] && docolor=1
        fi
        #(( docolor )) && echo -e "\e[31;1m\c"
        printf " %-10s" "$id"
        #(( docolor )) && echo -e "\e[0m\c"
    done
    echo
    
done
