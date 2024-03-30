import glob
import os
from Crypto.PublicKey import RSA
import logging
import colorlog

logger = logging.getLogger('ClientLogger')
logger.setLevel(logging.INFO)
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s[%(levelname)s]: %(message)s',
    log_colors={
        'INFO': 'cyan',
        'ERROR': 'red',
        'DEBUG': 'green',
    }
))
logger.addHandler(handler)

def generate_rsa_keys(flag=None):
    if flag:
        keys_folder_path = 'keys/'
        key_files = glob.glob(f'{keys_folder_path}*.pem')

        if len(key_files) == 2:
            private_key_path = None
            public_key_path = None

            for file in key_files:
                if 'private' in file:
                    private_key_path = file
                elif 'public' in file:
                    public_key_path = file
            if private_key_path and public_key_path:
                remove_keys(None, public_key_path, private_key_path)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    with open(filename, 'wb') as pem_file:
        pem_file.write(private_key)
    logger.info(f"Private key saved to {filename}")

def save_public_key(public_key, filename):
    with open(filename, 'wb') as pem_file:
        pem_file.write(public_key)
    logger.info(f"Public key saved to {filename}")

def remove_keys(id, publicKeyPath=None, privateKeyPath=None):
    if publicKeyPath and privateKeyPath:
        private_key_path = f'{privateKeyPath}'
        public_key_path = f'{publicKeyPath}'

        for path in [private_key_path, public_key_path]:
            try:
                os.remove(path)
                logger.info(f"Removed key: {path}")
            except FileNotFoundError:
                logger.error(f"Key file not found: {path}")
    else:
        private_key_path2 = f'keys/{id}_private_key.pem'
        public_key_path2 = f'keys/{id}_public_key.pem'

        for path in [private_key_path2, public_key_path2]:
            try:
                os.remove(path)
                logger.info(f"Removed key: {path}")
            except FileNotFoundError:
                logger.error(f"Key file not found: {path}")
