node {
  stage 'checkout git'
  checkout scm
  stage 'install dependencies'
  if ( !fileExists('ez_setup.py')){
      sh "wget https://bootstrap.pypa.io/ez_setup.py"
      sh "python ez_setup.py --user"
      sh "python -m easy_install -U --user vsc-install"
  }
  stage 'test'
  sh "python setup.py test"
}
