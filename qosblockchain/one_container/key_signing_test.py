from sawtooth_cli.sawadm import main as sawadm_keygen
from sawtooth_cli.sawtooth_keygen import main as sawtooth_keygen

import os
def ler_arquivo(file_name):

    try:
        dados = open(file_name,'r').read().strip()
    except:
        raise SyntaxError("ERROR: Check the file name > ", file_name)

    return dados

def criar_par_chaves_sawtooth(KEYS_LOCATION):
    #'<key-dir> defaults to ~/.sawtooth and <key-name> defaults to $USER.',os.environ.get('USER')
    username = os.environ.get('USER')
    KEYS_LOCATION = "/"+username+"/.sawtooth/keys/"
    
    if not os.path.exists(KEYS_LOCATION+username+".pub") or not os.path.exists(KEYS_LOCATION+username+".priv"):
        try:
            sawtooth_keygen(prog_name="fred_server", args=["keygen", "--f"]) ## salva em /etc/sawtooth/keys/validator.pub e .priv OPS, modificado para salvar em /keys/validator.pub e .priv
        except:
            raise SyntaxError("Não foi possível criar as chaves publicas e privadas")
    chave_publica = ler_arquivo(KEYS_LOCATION+username+".pub")
    chave_privada = ler_arquivo(KEYS_LOCATION+username+".priv")
    return chave_publica, chave_privada

def criar_par_chaves_sawadm(KEYS_LOCATION):

    try:
        if not os.path.exists(KEYS_LOCATION): 
            os.mkdir(KEYS_LOCATION)
    except:
        raise SyntaxError("Não foi possivel criar o folder: ", KEYS_LOCATION, " - make sure to run as root")
    
    if not os.path.exists(KEYS_LOCATION+"validator.pub") or not os.path.exists(KEYS_LOCATION+"validator.priv"):
        try:
            sawadm_keygen(prog_name="fred_server", args=["keygen", "--f"]) ## salva em /etc/sawtooth/keys/validator.pub e .priv OPS, modificado para salvar em /keys/validator.pub e .priv
        except:
            raise SyntaxError("Não foi possível criar as chaves publicas e privadas")

    chave_publica = ler_arquivo(KEYS_LOCATION+"validator.pub")
    chave_privada = ler_arquivo(KEYS_LOCATION+"validator.priv")

    return chave_publica, chave_privada

if __name__ == "__main__":

    KEYS_LOCATION = "/sawtooth_keys/"

    print(criar_par_chaves_sawtooth(KEYS_LOCATION))
    print(criar_par_chaves_sawadm(KEYS_LOCATION))