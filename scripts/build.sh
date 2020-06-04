#!/usr/bin/env sh

echo "Building Application"

# rm requirements.txt
# pipenv lock -r > ./src/build/requirements.txt
# pipenv lock -r > ./src/requirements.txt
pipenv lock -r > requirements.txt
sam build # -t templates/template.yml -b src/build

# pipenv lock -r > requirements.txt
# pipenv run pip install -r requirements.txt -t src/build/ --upgrade
# command cp -rf src/*.py src/build/
