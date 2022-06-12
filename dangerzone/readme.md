It is a project utilizing Open source 'Dangerzone'

This project includes HWP file extension a lot of koreans use.

Convert hwp to html through pyhwp and html to pdf through wkhtmltopdf.

Must install Korean Package.

-----------------------------------------------------------------------------------

If you want searchable PDF file. Execute following command for tesseract

docker run --network none -v [document_filename]:/tmp/input_file -v [safe_dir]:/safezone -e OCR=[ocr] -e OCR_LANGUAGE=[ocr_lang] [container_name] document-to-pdf.sh

ex)  

docker run --network none -v /root/dangerzone/input_file:/tmp/input_file -v /root/dangerzone/result:/safezone -e OCR=1 -e OCR_LANGUAGE=Hangul cap/test:0.0 document-to-pdf.sh

-----------------------------------------------------------------------------------
  
Or if you want flat PDF file, Excute following command

docker run --network none -v [document_filename]:/tmp/input_file -v [safe_dir]:/safezone [container_name] document-to-pdf.sh

ex)

docker run --network none -v /root/dangerzone/input_file:/tmp/input_file -v /root/dangerzone/result:/safezone cap/test:0.0 document-to-pdf.sh
