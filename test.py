from netifaces import AF_INET, ifaddresses, interfaces 

if __name__ == "__main__":

    CONTROLLER_INTERFACE = str("enp7s0")
    IPCv6 = str(ifaddresses(CONTROLLER_INTERFACE)[AF_INET][0]['addr'])

    print(ifaddresses(CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])