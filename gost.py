from tkinter import *
from tkinter import ttk


class KeyDict(dict):
    def keylist(self, keys, value):
        for key in keys:
            self[key] = value

class Main_window():
    def reverse(self, num):
        return "".join(reversed([num[i:i+2] for i in range(0, len(num), 2)]))
    
    def little_endian(self, num):
        res = ''
        for pack in reversed(range(0,len(num),8)):
            res = res + num[pack:pack+8]
        return self.reverse(res)

    def encrypt_ecb(self, input):
        input = input.zfill(16)

        A = int(input[ 8:16],16)
        B = int(input[ 0: 8],16)

        s_box = self.s_box

        d = KeyDict()
        d.keylist(('1',  '9', '17', '32'), self.K1) #dictionary of subkeys
        d.keylist(('2', '10', '18', '31'), self.K2)
        d.keylist(('3', '11', '19', '30'), self.K3)
        d.keylist(('4', '12', '20', '29'), self.K4)
        d.keylist(('5', '13', '21', '28'), self.K5)
        d.keylist(('6', '14', '22', '27'), self.K6)
        d.keylist(('7', '15', '23', '26'), self.K7)
        d.keylist(('8', '16', '24', '25'), self.K8)

        for index in range(1,33):

            key = (d[str(index)])

            F = bin(((A + key) & int('FFFFFFFF', 16)))[2:].zfill(32)

            F1 = s_box[0][int(F[28:32],2)]
            F2 = s_box[1][int(F[24:28],2)]
            F3 = s_box[2][int(F[20:24],2)]
            F4 = s_box[3][int(F[16:20],2)]
            F5 = s_box[4][int(F[12:16],2)]
            F6 = s_box[5][int(F[ 8:12],2)]
            F7 = s_box[6][int(F[ 4: 8],2)]
            F8 = s_box[7][int(F[ 0: 4],2)]

            F = F8 + F7 + F6 + F5 + F4 + F3 + F2 + F1
            F = F[11:32] + F[0:11]

            if index != 32 :
                An = int(F,2) ^ B
                Bn = A
            else :
                Bn = int(F,2) ^ B
                An = A

            A = An
            B = Bn

        output = hex(B << 32 | A)[2:].zfill(16)
        return output

    def decrypt_ecb(self, input):
        input = input.zfill(16)

        A = int(input[ 8:16],16)
        B = int(input[ 0: 8],16)

        s_box = self.s_box

        d = KeyDict()
        d.keylist(('1', '16', '24', '32'), self.K1) #dictionary of subkeys
        d.keylist(('2', '15', '23', '31'), self.K2)
        d.keylist(('3', '14', '22', '30'), self.K3)
        d.keylist(('4', '13', '21', '29'), self.K4)
        d.keylist(('5', '12', '20', '28'), self.K5)
        d.keylist(('6', '11', '19', '27'), self.K6)
        d.keylist(('7', '10', '18', '26'), self.K7)
        d.keylist(('8',  '9', '17', '25'), self.K8)


        for index in range(1,33):
            key = (d[str(index)])

            F = bin(((A + key) & int('FFFFFFFF', 16)))[2:].zfill(32)

            F1 = s_box[0][int(F[28:32],2)]
            F2 = s_box[1][int(F[24:28],2)]
            F3 = s_box[2][int(F[20:24],2)]
            F4 = s_box[3][int(F[16:20],2)]
            F5 = s_box[4][int(F[12:16],2)]
            F6 = s_box[5][int(F[ 8:12],2)]
            F7 = s_box[6][int(F[ 4: 8],2)]
            F8 = s_box[7][int(F[ 0: 4],2)]

            F = F8 + F7 + F6 + F5 + F4 + F3 + F2 + F1
            F = F[11:32] + F[0:11]

            if index != 32:
                An = int(F,2) ^ B
                Bn = A
            else:
                Bn = int(F,2) ^ B
                An = A

            A = An
            B = Bn

        output = hex(B << 32 | A)[2:].zfill(16)
        return output

    def encrypt(self):
        self.result_text.delete(1.0, END)

        with open(self.s_box_dict[self.s_box_var.get()]) as file:
            s_box_input = file.read()
        file.close()

        self.s_box = [[] for _ in range(8)]

        for index in range(0,16) :
            for row in range(0,8) :
                self.s_box[row].append(bin(int(s_box_input[index*2 + 32*row],16))[2:].zfill(4))

        key = self.reverse(self.key_var.get()[0:64])

        self.K8 = int(key[ 0: 8],16)
        self.K7 = int(key[ 8:16],16)
        self.K6 = int(key[16:24],16)
        self.K5 = int(key[24:32],16)
        self.K4 = int(key[32:40],16)
        self.K3 = int(key[40:48],16)
        self.K2 = int(key[48:56],16)
        self.K1 = int(key[56:64],16)

        input = self.base_text.get(1.0, END)[:-1]

        if self.method_var.get() == 'ECB mode':
            output = ''
            for block_num in range ((len(input[:-1])//16)+1):
                output = output + self.encrypt_ecb(input[0+block_num*16:16+block_num*16])

            self.result_text.insert(1.0, output)
            return output

        if self.method_var.get() == 'CNT mode':
            iv = self.reverse(self.iv_var.get()[0:16])

            result = self.encrypt_ecb(iv)

            C2 = int('01010104',16)
            C1 = int('01010101',16)

            N4 = int(result[ 0: 8],16)
            N3 = int(result[ 8:16],16)
            N4 =  (N4 + C2)     & int("FFFFFFFF", 16)
            N3 = ((N3 + C1 - 1) % int("FFFFFFFF", 16)) + 1
            N1 = N3
            N2 = N4

            gamma = self.encrypt_ecb(hex(N2 << 32 | N1)[2:].zfill(16))
            gamma = gamma[ 8:16] + gamma[ 0: 8]

            if input == '':
                input = '0'
            input = self.little_endian(input)

            output = hex((int(input,16)) ^ (int(gamma,16)))[2:].zfill(16)

            N1 = output[ 0: 8]
            N2 = output[ 8:16]

            output = self.little_endian(output)

            self.result_text.insert(1.0, output)
            return output

    def decrypt(self):
        self.result_text.delete(1.0, END)

        with open(self.s_box_dict[self.s_box_var.get()]) as file:
            s_box_input = file.read()
        file.close()

        self.s_box = [[] for _ in range(8)]

        for index in range(0,16) :
            for row in range(0,8) :
                self.s_box[row].append(bin(int(s_box_input[index*2 + 32*row],16))[2:].zfill(4))

        key = self.reverse(self.key_var.get()[0:64])

        self.K8 = int(key[ 0: 8],16)
        self.K7 = int(key[ 8:16],16)
        self.K6 = int(key[16:24],16)
        self.K5 = int(key[24:32],16)
        self.K4 = int(key[32:40],16)
        self.K3 = int(key[40:48],16)
        self.K2 = int(key[48:56],16)
        self.K1 = int(key[56:64],16)

        input = self.base_text.get(1.0, END)[:-1]

        if self.method_var.get() == 'ECB mode':
            output = ''
            for block_num in range ((len(input[:-1])//16)+1):
                output = output + self.decrypt_ecb(input[0+block_num*16:16+block_num*16])
            self.result_text.insert(1.0, output)
            return output
        if self.method_var.get() == 'CNT mode':
            self.encrypt()


    def __init__(self):
        self.window = Tk()
        self.window.resizable(False, False)

        self.window.title('GOST 28147-89 encoder')
        frame = ttk.Frame(self.window, padding='5 5 5 5')
        frame.grid (column=0, row=0, sticky=(N,W,E,S))

        self.method_var = StringVar()
        self.s_box_var  = StringVar()
        self.key_var    = StringVar()
        self.iv_var     = StringVar()
        self.base_var   = StringVar()

        self.method_var.set('ECB mode')
        self.s_box_var.set('id-Gost28147-89-CryptoPro-A-ParamSet')
        self.key_var.set('A0C84911FEB6AA546950EC7C532750464C77FAF35C071F47A457DDD152EE7DD0')
        self.iv_var.set('71EF0B1F3BE0394F')

        self.s_box_dict = { 'id-Gost28147-89-CryptoPro-A-ParamSet' : 'S_box/box_a',
                            'id-GostR3411-94-TestParamSet'         : 'S_box/box_t',
                            'id-tc26-gost-28147-param-Z'           : 'S_box/box_z'
        }


        self.row = 0
        def_pady=5

        method_label = ttk.Label(frame, text='Encryption mode').\
        grid(row=self.row, column=0, sticky='W', pady=def_pady)

        enc_method = ttk.Combobox(frame,
            textvariable=self.method_var,
            values=list(['ECB mode', 'CNT mode']),
            state='readonly',
            width=24)
        enc_method.grid(row=self.row, column=1, sticky='W', padx=5, pady=def_pady)

        s_box_label = ttk.Label(frame, text='S-box')
        s_box_label.grid(row=self.row, column=2, sticky='W', pady=def_pady)

        s_box_list = ttk.Combobox(frame,
            textvariable=self.s_box_var,
            values=list(self.s_box_dict.keys()),
            state='readonly',
            width=36)
        s_box_list.grid(row=self.row, column=3, sticky='W', padx=5, pady=def_pady)

        self.row += 1

        key_label = ttk.Label(frame, text='Encryption key')
        key_label.grid(row=self.row, column=0, sticky='W', pady=def_pady)

        key_entry = ttk.Entry(frame, textvariable=self.key_var, width=30)
        key_entry.grid(row=self.row, column=1, columnspan=3, sticky='NWES', padx=5, pady=def_pady)

        self.row += 1

        iv_label = ttk.Label(frame, text='Initialization vector')
        iv_label.grid(row=self.row, column=0, sticky='W', pady=def_pady)

        iv_entry = ttk.Entry(frame, state='disabled', textvariable=self.iv_var, width=30)
        iv_entry.grid(row=self.row, column=1, sticky='NWES', padx=5, pady=def_pady)
        enc_method.bind("<<ComboboxSelected>>", lambda event: \
            iv_entry.config(state='normal') if self.method_var.get() == 'CNT mode'\
            else iv_entry.config(state='disabled'))

        self.row += 1

        base_label = ttk.Label(frame, text='Input text: 0x')
        base_label.grid(row=self.row, column=0, sticky='W', pady=def_pady)

        self.row += 1

        self.base_text = Text(frame, height=10, width=60)
        self.base_text.grid(row=self.row, column=0, columnspan=4 ,sticky='NWES', padx=5, pady=def_pady)

        self.row += 1

        encode_button = ttk.Button(frame, text='Encrypt',
            command=lambda: self.encrypt())
        encode_button.grid(row=self.row, column=0, columnspan=2 ,sticky='NWES', padx=5, pady=def_pady)

        decode_button = ttk.Button(frame, text='Decrypt',
            command=lambda: self.decrypt())
        decode_button.grid(row=self.row, column=2, columnspan=2 ,sticky='NWES', padx=5, pady=def_pady)

        self.row += 1

        result_label = ttk.Label(frame, text='Result:')
        result_label.grid(row=self.row, column=0, sticky='W', pady=def_pady)

        self.row += 1

        self.result_text = Text(frame, height=10, width=60)
        self.result_text.grid(row=self.row, column=0, columnspan=4 ,sticky='NWES', padx=5, pady=def_pady)


Main_window().window.mainloop()
