'''
Ida python script based on AstaGuilStringSlayer script made by researcher -> Xienim.
TW: https://twitter.com/Hachiman_Xienim
script: https://github.com/Xienim/AstaGuilStringSlayer
'''


import ida_bytes
import idautils
import idc

def search_offset(x):
    #get address of encrypted string that's moved into eax
    if ida_bytes.get_byte(prev_head(x)) == 0xB8:
        return ida_bytes.get_dword(prev_head(x)+1)
    #get address from string table that's moved into eax
    if ida_bytes.get_word(prev_head(x)) == 0x048B:
        return ida_bytes.get_dword(ida_bytes.get_dword(prev_head(x)+3)) 
    return 0   

def get_string_size(address):
    size = ida_bytes.get_dword(address-4)
    return (size*2)
    
def set_string_type(address):
    #undefine range to be sure we set the entire string correctly
    ida_bytes.del_items(address, DELIT_EXPAND, get_string_size(address))
    #wait for del_items changes to propagate
    ida_auto.auto_wait()
    ida_bytes.create_strlit(address,0, ida_nalt.STRTYPE_C_16)


def string_to_hex(string):
    hex_string = ""
    for char in string:
        hex_value = hex(ord(char))[2:]
        hex_string += hex_value.zfill(2)
    return hex_string


def decrypter(var1, var2):
    result = ""
    result1 = ""
    result2 = ""
    stream = ""
    skiper5 = True
    var2_index = 0
    prev_hex_var1 = None

    for i in range(0, len(var1), 2):
        if skiper5:
            skiper5 = False
            prev_hex_var1 = var1[i:i+2]
        else:
            hex_var1 = var1[i:i+2]
            hex_var2 = hex(ord(var2[var2_index % len(var2)]))
            var2_index += 1
            xor_result = hex(int(hex_var1, 16) ^ int(hex_var2, 16))

            if int(xor_result, 16) <= int(prev_hex_var1, 16):
                if int(xor_result, 16) > int(prev_hex_var1, 16):
                    pass
                else:
                    xor_result = hex(int(xor_result, 16) + 0xFF)[2:]
                    xor_result = hex(int(xor_result, 16) - int(prev_hex_var1, 16))[2:]
                    result += xor_result
            else:
                sub_result = hex(int(xor_result, 16) - int(prev_hex_var1, 16))
                result += sub_result[2:]

            prev_hex_var1 = hex_var1
    result = result[::-1]
    result = ''.join([result[i:i+2][::-1] for i in range(0, len(result), 2)])
    
    for x in range(0, len(result), 2):
        hex_result1 = result[x:x+2]
        result1 += hex((int(hex_result1,16) - 0x0A) ^ 0xFF )[2:]
    
    prev_hex_var2 = None
    skiper3 = True
    for c in range(0, len(result1), 2):
        if skiper3:
            skiper3 = False
            prev_hex_var2 = hex(int(result1[c:c+2], 16) - 0x41)[2:]
            skiper = 0      
        else:
            if skiper == 0:
                hex_var3 = result1[c:c+2] 
                local1 = hex(int(hex_var3, 16) - 0x41)
                local2 = hex(int(local1, 16) * 0x4 )
                local3 = hex(int(local2, 16) + int(local1, 16) )
                local4 = hex(int(local3, 16) * 0x4 )
                local13 = hex(int(local4, 16) + int(local3, 16) )
                skiper = 1
            else:
                local5 = result1[c:c+2]
                local6 = hex(int(local5, 16) - 0x41)
                local7 = hex(int(local6, 16) + int(local13, 16))
                local8 = hex(int(local7, 16) - int(prev_hex_var2, 16))
                stream += hex(int(local8,16) - 0x64)
                skiper = 0
                
    return stream


key = ida_kernwin.ask_text(10, "", "Enter string decryption key")
if key == None:
    ida_kernwin.warning("You did not specify a key")
    
mw_string_decrypt = ida_kernwin.ask_long(0x00, "Enter address of string decrypt function")
if mw_string_decrypt == None:
    ida_kernwin.warning("You did not specify a function address")
    
#Get xrefs to string decryption function
xrefs_decrypt = set(idautils.CodeRefsTo(mw_string_decrypt,0))
if len(xrefs_decrypt) < 3:
    ida_kernwin.warning("Too little xrefs - did you pick the right function?")

for xref in xrefs_decrypt:
    offset = search_offset(xref)
    if offset > 0:
        print('Encrypted string at ', hex(offset))
        set_string_type(offset)
        string_enc = ida_bytes.get_strlit_contents(offset, get_string_size(offset), STRTYPE_C_16)
        result = decrypter(string_enc, key)  #this key must be retrieved from each sample; getting it automatically is in my todo list
        result = result.replace("0x", "")
        result = result.replace("x", "")
        result_chars = ''.join([chr(int(result[i:i+2], 16)) for i in range(0, len(result), 2)])
        print('Setting decrypted string as comment at: ', hex(prev_head(xref)))
        ida_bytes.set_cmt(prev_head(xref), result_chars, 0)
        print("{} ---> {}".format(result_chars,string_enc))
    else:
        print('Could not find string from ', hex(xref))
