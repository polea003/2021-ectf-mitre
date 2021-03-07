#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

import secrets

secretsGen = secrets.SystemRandom()

a = str(secretsGen._randbelow(255))
f = open("/data1", "w")
f.write(a)
f.close()

a = str(secretsGen._randbelow(255))
f = open("/data2", "w")
f.write(a)
f.close()

a = str(secretsGen._randbelow(255))
f = open("/data3", "w")
f.write(a)
f.close()

a = str(secretsGen._randbelow(255))
f = open("/data4", "w")
f.write(a)
f.close()