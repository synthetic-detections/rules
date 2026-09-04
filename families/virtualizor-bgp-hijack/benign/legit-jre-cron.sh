#!/bin/sh
# legitimate: check java version, touch authorized_keys for a real admin
java -version
grep -c ssh /home/admin/.ssh/authorized_keys
ls -l /usr/local/virtualizor/globals.php
