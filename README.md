Installation:

to install run: ```git clone https://github.com/gibler1/TOTP_bash.git & export PATH+=:"$(pwd)/TOTP_bash/src"```

to add script path permanently to PATH run ```echo "export PATH+=:""$(pwd)/TOTP_bash/src" >> ~/.bashrc```

USAGE:

to use place TOTP and totp_gen.sh file in the same folder then execute ```TOTP -a accountName:private_key``` to add an account and execute ```TOTP -p``` to get the TOTP tokens for all accounts
