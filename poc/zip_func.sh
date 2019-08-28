#!/bin/bash
set -e

cd vuln_lambda
rm -rf vuln_lambda.zip

cd package/
zip -r9 ${OLDPWD}/vuln_lambda.zip .

cd $OLDPWD
zip -g vuln_lambda.zip vulnLambda.py