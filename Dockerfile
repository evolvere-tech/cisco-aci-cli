FROM sihart/acli_auto_int:0.4

COPY acli.py /cisco-aci/

CMD python cisco-aci/acli.py
