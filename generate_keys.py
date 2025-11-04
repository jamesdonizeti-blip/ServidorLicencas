import os

print("Gerando chaves RSA...")

os.system("openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048")
os.system("openssl rsa -in private.pem -pubout -out public.pem")

print("Chaves geradas com sucesso!")
