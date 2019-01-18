import pefile

exe_path = input("Enter path to exe: ")
pe = pefile.PE(exe_path)


for section in pe.sections:
    if section.Name == b'.rdata\x00\x00':
        print(section.Name.decode('utf-8'))
        print("\tMisc_PhysicalAddress: " + str("\t" + hex(section.Misc_PhysicalAddress)) + "\t\tРазмер секции в памяти. Если это значение больше SizeOfRawData, то секция дополняется в памяти нулевыми байтами.")
        print("\tVirtualAddress: " + str("\t\t" + hex(section.VirtualAddress))+ "\t\tRVA секции в памяти.")
        print("\tSizeOfRawData: " + str("\t\t\t" + hex(section.SizeOfRawData))+ "\t\tРазмер секции в файле. Всегда кратен FileAlignment из необязательного заголовка. Если секция содержит только неинициализированные данные, то это поле равно нулю.")
        print("\tPointerToRawData: " + str("\t\t" + hex(section.PointerToRawData))+ "\t\tСмещение в файле до начала данных секций. Всегда кратно FileAlignment из необязательного заголовка. Если секция содержит только неинициализированные данные, то это поле равно нулю.")
        print("\tPointerToRelocations: " + str("\t" + hex(section.PointerToRelocations))+ "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tPointerToLinenumbers: " + str("\t" + hex(section.PointerToLinenumbers))+ "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tNumberOfRelocations: " + str("\t" + hex(section.NumberOfRelocations))+ "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tNumberOfLinenumbers: " + str("\t" + hex(section.NumberOfLinenumbers))+ "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tCharacteristics: " + str("\t\t" + hex(section.Characteristics))+ "\tАтрибуты секции.")
    elif section.Name == b'.rsrc\x00\x00\x00':
        print(section.Name.decode('utf-8'))
        print("\tMisc_PhysicalAddress: " + str("\t" + hex(
            section.Misc_PhysicalAddress)) + "\t\tРазмер секции в памяти. Если это значение больше SizeOfRawData, то секция дополняется в памяти нулевыми байтами.")
        print("\tVirtualAddress: " + str("\t\t" + hex(section.VirtualAddress)) + "\t\tRVA секции в памяти.")
        print("\tSizeOfRawData: " + str("\t\t\t" + hex(
            section.SizeOfRawData)) + "\t\tРазмер секции в файле. Всегда кратен FileAlignment из необязательного заголовка. Если секция содержит только неинициализированные данные, то это поле равно нулю.")
        print("\tPointerToRawData: " + str("\t\t" + hex(
            section.PointerToRawData)) + "\t\tСмещение в файле до начала данных секций. Всегда кратно FileAlignment из необязательного заголовка. Если секция содержит только неинициализированные данные, то это поле равно нулю.")
        print("\tPointerToRelocations: " + str(
            "\t" + hex(section.PointerToRelocations)) + "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tPointerToLinenumbers: " + str(
            "\t" + hex(section.PointerToLinenumbers)) + "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tNumberOfRelocations: " + str(
            "\t" + hex(section.NumberOfRelocations)) + "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tNumberOfLinenumbers: " + str(
            "\t" + hex(section.NumberOfLinenumbers)) + "\t\t\tВ исполняемых файлах это поле всегда равно нулю.")
        print("\tCharacteristics: " + str("\t\t" + hex(section.Characteristics)) + "\tАтрибуты секции.")
