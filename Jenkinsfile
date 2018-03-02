#!/usr/bin/env groovy

node {
    stage 'Checkout'
    checkout scm
    stage 'install dependencies'
    sh "wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py"
    sh "python get-pip.py --user"
    sh "python -m pip install -U --user vsc-install"
    stage 'cleanup'
    sh "git clean -fd"
    stage 'test'
    sh "python setup.py test"
}
