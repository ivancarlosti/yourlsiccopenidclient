# PHP image used by the end to end test (YOURLS needs pdo_mysql).
FROM php:8.4-cli-alpine

RUN apk add --no-cache $PHPIZE_DEPS \
    && docker-php-ext-install pdo_mysql \
    && apk del $PHPIZE_DEPS
