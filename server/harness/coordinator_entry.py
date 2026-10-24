#!/usr/bin/python3
import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
from fixed_entries import coordinator, child
if __name__=='__main__':
    sys.exit(coordinator() if 'coordinator'=='coordinator' else child('coordinator'))
