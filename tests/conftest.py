from os import path

import dotenv


dotenv.load_dotenv(path.join(path.dirname(__file__), '../.env'))
