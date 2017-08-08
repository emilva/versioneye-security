[![Circle CI](https://circleci.com/gh/versioneye/versioneye-security.svg?style=svg)](https://circleci.com/gh/versioneye/versioneye-security) [![Dependency Status](https://www.versioneye.com/user/projects/5964814d6725bd004c4b52d4/badge.svg?style=flat-square)](https://www.versioneye.com/user/projects/5964814d6725bd004c4b52d4)

# VersionEye Security

This repo contains the security crawlers for [VersionEye](https://www.versioneye.com) written in ruby.
Currently this projects has data fetchers for:

 - Java ([NVD](http://nvd.nist.gov/))
 - Java ([VictimsDB](https://github.com/victims/victims-cve-db/))
 - Python ([VictimsDB](https://github.com/victims/victims-cve-db/))
 - Ruby ([Ruby Advisory DB](https://github.com/rubysec/ruby-advisory-db.git))
 - PHP ([SensioLabs DB](https://github.com/FriendsOfPHP/security-advisories.git))
 - PHP Magento ([Magento Security Advisory](https://github.com/Cotya/magento-security-advisories.git))
 - Node.JS ([NodeSecurity](https://nodesecurity.io/))
 - Node.JS ([Snyk](https://snyk.io/))
 - JavaScript ([Retire.js](https://github.com/retireJS/retire.js))
 - Rust ([Rust Advisory](https://github.com/RustSec/advisory-db))

## Start the backend services for VersionEye

This project contains a [docker-compose.yml](docker-compose.yml) file which describes the backend systems
of VersionEye. You can start the backend systems like this:

```
docker-compose up -d
```

That will start:

 - MongoDB
 - RabbitMQ
 - ElasticSearch
 - Memcached

For persistence you should comment in and adjust the mount volumes in [docker-compose.yml](docker-compose.yml)
for MongoDB and ElasticSearch. If you are not interested in persisting the data on your host you can
let it untouched.

Shutting down the backend systems works like this:

```
docker-compose down
```

## Configuration

All important configuration values are read from environment variable. Before you start
VersioneyeCore.new you should adjust the values in [scripts/set_vars_for_dev.sh](scripts/set_vars_for_dev.sh)
and load them like this:

```
source ./scripts/set_vars_for_dev.sh
```

The most important env. variables are the ones for the backend systems, which point to MongoDB, ElasticSearch,
RabbitMQ and Memcached.

## Install dependencies

If the backend services are all up and running and the environment variables are set correctly
you can install the dependencies with `bundler`. If `bundler` is not installed on your machine
run this command to install it:

```
gem install bundler
```

Then you can install the dependencies like this:

```
bundle install
```

## Rake Tasks

Get a list of all rake tasks:

```
rake -T
```

Crawl for Java security vulnerabilities:

```
rake versioneye:crawl_java_security
```

## Tests

The tests for this project are running after each `git push` on [CircleCI](https://circleci.com/gh/versioneye/versioneye-security)!
First of all a Docker image is build for this project and the tests are executed inside of a Docker container.
For more details take a look to the [Dockerfile](Dockerfile) and the [circle.yml](circle.yml) file in the root directory!

If the Docker containers for the backend systems are running locally, the tests can be executed locally
with this command:

```
./scripts/run_tests_local.sh
```

Make sure that you followed the steps in the configuration section, before you run the tests!

All Files covered to 95.82%.

## Support

For commercial support send a message to `support@versioneye.com`.

## AGPL-v3 License

Copyright (c) 2016 VersionEye GmbH

The contents of this repository is available under the AGPL-v3 license, see the [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.en.html) for full details.
