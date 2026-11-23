"""Operator-only connectivity diagnostics; no samples or credentials are printed."""
from pathlib import Path
import os
import sys
from dotenv import dotenv_values
from .config import settings, Settings
from .provider_status import check


def main():
    root=Path(__file__).resolve().parents[2]
    sys.path.insert(0,str(root/'scripts'))
    from existing_cuckoo import configure
    values={**{k:v for k,v in dotenv_values(root/'.env').items() if v is not None},**os.environ}
    configure(values,root)
    resolved=Settings(**{k.lower():v for k,v in values.items()})
    for key,value in resolved.model_dump().items():setattr(settings,key,value)
    for name in ('sandbox','virustotal','hybrid-analysis'):
        result=check(name,refresh=True)
        print(result['name']+': '+result['status']+' — '+result.get('message',''),flush=True)
    print('No samples were submitted.',flush=True)


if __name__=='__main__': main()
