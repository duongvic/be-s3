import yaml
import os
from pathlib import Path
from dotenv import load_dotenv


class Config:

    # get info from file
    ROOT_DIR = Path(__file__).parent
    load_dotenv()
    # fileName = 's3-config_.yaml'
    fileName = os.getenv('ENV_CONFIG')
    # print(type(fileName))
    print(fileName)
    DB_PATH = os.path.join(ROOT_DIR, fileName)
    with open(DB_PATH, 'r') as f:
        try:
            config = yaml.safe_load(f)
            # print(config['s3_fox_clound'])
        except yaml.YAMLError as exc:
            print(exc)


CONF = Config()
