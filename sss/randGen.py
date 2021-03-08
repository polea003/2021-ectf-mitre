#script generates a random deployment passcode

import secrets

secretsGen = secrets.SystemRandom()

a = str(secretsGen._randbelow(4294967295))
f = open("/secrets/data.txt", "w")
f.write(a)
f.close()