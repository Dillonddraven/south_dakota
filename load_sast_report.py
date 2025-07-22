import json
import os

def load_sast_report(filepath):
    print("Loading SAST Report from local json file ")

    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)
    with open (filepath, 'r', encoding='utf-8') as json_file:
        try:
            data= json.load(json_file)
            return data
        except json.decoder.JSONDecodeError as e:
            raise json.JSONDecodeError(f"erorr decoding json file: {e}", e.doc, e.pos)