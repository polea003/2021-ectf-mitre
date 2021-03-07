# 2021 Collegiate eCTF
# SCEWL Bus Controller build Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

ARG DEPLOYMENT


###################################################################
# if you want to copy files from the sss container,               #
# first create an intermediate stage:                             #
#                                                                 #
FROM ${DEPLOYMENT}/sss:latest as sss                                   
#                                                                 #
# Then see box below                                              #
###################################################################

# load the base controller image
FROM ${DEPLOYMENT}/controller:base

# map in controller to /sed
# NOTE: only cpu/ and its subdirectories in the repo are accessible to this Dockerfile as .
ADD . /sed

###################################################################
# Copy files from the SSS container                               #
# 
# COPY --from=sss randGen.py /sed/randGen.py                                                                  #
COPY --from=sss /secrets/data.txt /sed/sed.secret     
#                                                                 #
###################################################################
# IT IS NOT RECOMMENDED TO KEEP DEPLOYMENT-WIDE SECRETS IN THE    #
# SED FILE STRUCTURE PAST BUILDING, SO CLEAN UP HERE AS NECESSARY #
###################################################################

# generate any other secrets and build controller
ARG SCEWL_ID
COPY --from=sss /secrets/${SCEWL_ID}.data1 /sed/sed.data1
COPY --from=sss /secrets/${SCEWL_ID}.data2 /sed/sed.data2
COPY --from=sss /secrets/${SCEWL_ID}.data3 /sed/sed.data3
COPY --from=sss /secrets/${SCEWL_ID}.data4 /sed/sed.data4
WORKDIR /sed
# RUN while read LINE; do echo $LINE; done < sed.secret
RUN make SCEWL_ID=${SCEWL_ID} SECRET=`cat sed.secret` DATA1=`cat sed.data1` DATA2=`cat sed.data2` DATA3=`cat sed.data3` DATA4=`cat sed.data4`
RUN mv /sed/gcc/controller.bin /controller

# NOTE: If you want to use the debugger with the scripts we provide, 
#       the ELF file must be at /controller.elf
RUN mv /sed/gcc/controller.axf /controller.elf