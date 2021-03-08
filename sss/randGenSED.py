#script generates a random SED registration number

import secrets

secretsGen = secrets.SystemRandom()

a = str(secretsGen._randbelow(4294967295))
f = open("/secrets/data1", "w")
f.write(a)
f.close()