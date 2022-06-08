from ByteGrotto import ByteGrotto


def main():
    bg = ByteGrotto(pe_path=<path to binary to modify>, pe_ouput_name=<output exe name>)
    bg.generate_adversarial_pe()

if __name__ == '__main__':
    main()