FROM sihart/acli_auto_int:0.4

COPY acli.py /cisco-aci/
COPY settings/aci_settings.py /cisco-aci/settings/

CMD touch cisco-aci/settings/__init__.py && python cisco-aci/acli.py
