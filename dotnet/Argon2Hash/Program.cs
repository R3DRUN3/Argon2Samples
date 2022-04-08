using Isopoh.Cryptography.Argon2;
using static System.Console;

WriteLine("Insert a password to hash: ");
string? pwd = ReadLine();
if(pwd != null){
    var passwordHash = Argon2.Hash(pwd); //Using Default Vaule
    WriteLine($"Hashed Password: \n{passwordHash}\n");
    while (true){
        WriteLine("Insert password to verify: ");
        string? pwdToVerify = ReadLine();
        if(pwdToVerify != null){
            if (Argon2.Verify(passwordHash, pwdToVerify))
            {
                WriteLine("Is the original password!!! (✯ ◡ ✯) ");
            }else{
                WriteLine("This is not the original password  ( ཀ ʖ̯ ཀ )");
            }
        }
    }
}