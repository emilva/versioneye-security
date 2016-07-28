#!/bin/bash

# MongoDB
export DB_PORT_27017_TCP_ADDR=127.0.0.1
export DB_PORT_27017_TCP_PORT=27017

# ElasticSearch
export ES_PORT_9200_TCP_ADDR=127.0.0.1
export ES_PORT_9200_TCP_PORT=9200

# RabbitMQ
export RM_PORT_5672_TCP_ADDR=127.0.0.1
export RM_PORT_5672_TCP_PORT=5672

# Memcache
export MC_PORT_11211_TCP_ADDR=127.0.0.1
export MC_PORT_11211_TCP_PORT=11211

export RAILS_ENV="development"
echo "Rails mode: $RAILS_ENV"
