from argon2 import PasswordHasher as ph

my_password = input('\nInsert your password: ')
pass_hasher = ph()
hash = pass_hasher.hash(my_password)
print(f'Argon2 hashed password: {hash}\n')
while True:
    is_this_the_original_pwd = input('Insert a password to verify: ')
    try:
        comparison_result = pass_hasher.verify(hash, is_this_the_original_pwd)
        print(f'Is this the original password? ====> {comparison_result}\n')
    except Exception as e:
        print(f'{e}\n')


