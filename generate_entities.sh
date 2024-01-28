#!/usr/bin/env zsh

DATABASE_URL=$1

sea-orm-cli generate entity -u "$DATABASE_URL" -o persistence-orm/src/entities --date-time-crate time