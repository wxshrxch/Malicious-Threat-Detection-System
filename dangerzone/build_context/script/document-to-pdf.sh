#!/bin/bash

# Do the conversion without root
/usr/bin/sudo -u user python3 /usr/local/bin/document-to-pixels.py
RETURN_CODE=$?
if [ $RETURN_CODE -ne 0 ]; then
    echo ""
    exit $RETURN_CODE
fi

/usr/bin/sudo OCR=$OCR OCR_LANGUAGE=$OCR_LANGUAGE -u user python3 /usr/local/bin/pixels-to-pdf.py
RETURN_CODE=$?
if [ $RETURN_CODE -ne 0 ]; then
    echo ""
    exit $RETURN_CODE
fi

# Move converted files into /safezone
/bin/mv /tmp/safe-output.pdf /safezone
