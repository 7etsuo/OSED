# snowcra5h@icloud.com
# Creates the files.txt document
# that gets parsed by install.ps1
#
# snowcrash - OSED 2022

#!/bin/bash

if [ -f files.txt  ]; then
    rm files.txt
fi

    files=$(find . -type f)
    files=${files//.\//}

    echo "$files" | while read -r line; do
        echo "$line" >> files.txt
done

echo "now run: updog -p 9000"
