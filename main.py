from ByteGrotto import ByteGrotto


def main():
    bg = ByteGrotto(pe_path="../Mallard/MLSEC_2021_malware/010", pe_ouput_name="new.exe")
    bg.generate_adversarial_pe()

if __name__ == '__main__':
    main()