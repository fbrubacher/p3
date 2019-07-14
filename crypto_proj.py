import hashlib
import json
import math
import os
import random
# You may NOT alter the import list!!!!


class CryptoProject(object):

    def __init__(self):
        # TODO: Change this to YOUR Georgia Tech student ID!!!
        # Note that this is NOT your 9-digit Georgia Tech ID
        self.student_id = 'bdornier3'  # for test_crypto_proj_1.py
        # self.student_id = 'ctaylor'  # for test_crypto_proj_2.py

    def get_student_id_hash(self):
        return hashlib.sha224(self.student_id.encode('UTF-8')).hexdigest()

    def get_all_data_from_json(self, filename):
        data = None
        base_dir = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(base_dir, filename), 'r') as f:
            data = json.load(f)
        return data

    def get_data_from_json_for_student(self, filename):
        data = self.get_all_data_from_json(filename)
        name = self.get_student_id_hash()
        if name not in data:
            print(self.student_id + ' not in file ' + filename)
            return None
        else:
            return data[name]

    # BEGIN HELPER FUNCTIONS
    def euclidian(self, a, b):
        if a == 0:
            return (b, 0, 1)
        g, x, y = self.euclidian(b % a, a)
        new_x =  y - x 
        new_x = y - x * (b // a)
        return (g, new_x, x)

    def root_bs(self, n):
        low = 0
        high = n
        while low < high:
            mid = (low+high)//2
            if mid**3 < n:
                low = mid+1
            else:
                high = mid
        return low
    # END HELPER FUNCTIONS

    def decrypt_message(self, N, e, d, c):
        # TODO: Implement this function for Task 1
        m = hex(pow(c, d, N))
        return m

    def crack_password_hash(self, password_hash, weak_password_list):
        for p in weak_password_list:
            for s in weak_password_list:
                 hp = hashlib.sha256(p.encode() + s.encode()).hexdigest()
                 if hp == password_hash:
                    return p, s

    def get_factors(self, n):
        p = 0
        q = 0

        root = int(math.sqrt(n))
        if (root % 2 == 0):
            root = root -1
        c = root
        for c in range(root, 0, -2):
            if (n % c == 0):
                p = c
                break
        q = int(n/p)
        return p, q

    def get_private_key_from_p_q_e(self, p, q, e):
        p = p -1
        q = q -1
        phi = p * q
        _, i, _ = self.euclidian(e, phi)
        res = ((i % phi) + phi) % phi
        return res

    def is_waldo(self, n1, n2):
        p, _, _ = self.euclidian(n1, n2) 
        return p > 1


    def get_private_key_from_n1_n2_e(self, n1, n2, e):
        p, _, _ = self.euclidian(n1, n2) 
        q = n1 // p
        p = p - 1
        q = q - 1
        phi = p * q
        _, d, _ = self.euclidian(e, phi)
        return ((d % phi) + phi) % phi

        return d

    def recover_msg(self, N1, N2, N3, C1, C2, C3):
        _, inv, _ = self.euclidian(N2 * N3, N1)
        res1 = ((inv % N1) + N1) % N1
        _, inv, _ = self.euclidian(N1 * N3, N2)
        res2 = ((inv % N2) + N2) % N2
        _, inv, _ = self.euclidian(N1 * N2, N3)
        res3 = ((inv % N3) + N3) % N3

        N = (N1 * N2 * N3)
        Cs = (C1 * N2 * N3 * res1 + C2 * N1 * N3 * res2 + C3 * N1 * N2 * res3)
        C = Cs % N
        return self.root_bs(C)

    def task_1(self):
        data = self.get_data_from_json_for_student('keys4student_task_1.json')
        N = int(data['N'], 16)
        e = int(data['e'], 16)
        d = int(data['d'], 16)
        c = int(data['c'], 16)

        m = self.decrypt_message(N, e, d, c)
        return m

    def task_2(self):
        data = self.get_data_from_json_for_student('hashes4student_task_2.json')
        password_hash = data['password_hash']

        # The password file is loaded as a convenience
        weak_password_list = []
        base_dir = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(base_dir, 'top_passwords.txt'), 'r', encoding='UTF-8-SIG') as f:
            pw = f.readline()
            while pw:
                weak_password_list.append(pw.strip('\n'))
                pw = f.readline()

        password, salt = self.crack_password_hash(password_hash, weak_password_list)

        return password, salt

    def task_3(self):
        data = self.get_data_from_json_for_student('keys4student_task_3.json')
        n = int(data['N'], 16)
        e = int(data['e'], 16)

        p, q = self.get_factors(n)
        d = self.get_private_key_from_p_q_e(p, q, e)

        return hex(d).rstrip('L')

    def task_4(self):
        all_data = self.get_all_data_from_json('keys4student_task_4.json')
        student_data = self.get_data_from_json_for_student('keys4student_task_4.json')
        n1 = int(student_data['N'], 16)
        e = int(student_data['e'], 16)

        d = 0
        waldo = 'Dolores'

        for classmate in all_data:
            if classmate == self.get_student_id_hash():
                continue
            n2 = int(all_data[classmate]['N'], 16)

            if self.is_waldo(n1, n2):
                waldo = classmate
                d = self.get_private_key_from_n1_n2_e(n1, n2, e)
                break

        return hex(d).rstrip("L"), waldo

    def task_5(self):
        data = self.get_data_from_json_for_student('keys4student_task_5.json')
        N1 = int(data['N0'], 16)
        N2 = int(data['N1'], 16)
        N3 = int(data['N2'], 16)
        C1 = int(data['C0'], 16)
        C2 = int(data['C1'], 16)
        C3 = int(data['C2'], 16)

        m = self.recover_msg(N1, N2, N3, C1, C2, C3)
        # Convert the int to a message string
        msg = bytes.fromhex(hex(m).rstrip('L')[2:]).decode('UTF-8')

        return msg