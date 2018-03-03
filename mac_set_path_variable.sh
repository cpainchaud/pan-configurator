#!/usr/bin/env bash

FOLDER_PATH=$PWD

echo "START \"set path variables\"" \
&& echo "" \
&& php -v \
&& echo "" \
&& echo "prepare php.ini and set include path" \
&& sudo cp -f /etc/php.ini.default /etc/php.ini \
&& sudo chmod u+w /etc/php.ini \
&& echo "include_path = \".:/php/includes:${FOLDER_PATH}\"" | sudo tee -a /etc/php.ini \
&& echo "" \
&& echo "" \
&& echo "check if everyting is successfully installed" \
&& php -r "require('lib/panconfigurator.php');print \"PAN-C LIBRARY - OK INSTALL SUCCESSFUL\n\";" \
&& echo "" \
&& echo "" \
&& echo "set user bash profile"   \
&& echo "source \"${FOLDER_PATH}/utils/alias.sh\"" >> ~/.profile \
&& echo "source \"${FOLDER_PATH}/utils/alias.sh\"" >> ~/.bash_profile \
&& echo "" \
&& echo "" \
&& echo "END script"
