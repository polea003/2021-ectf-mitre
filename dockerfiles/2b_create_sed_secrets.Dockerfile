# 2021 Collegiate eCTF
# Generate SED secrets Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# load current SSS container to modify
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
# NOTE: to maximize the useage of container cache, use ADD to map in only the files/directories you need
#       (e.g. only mapping in the SED directory rather than the entire repo)

# do here whatever you need here to create secrets for the new SED that the SSS needs access to


WORKDIR /secrets

# RUN mkdir ${SCEWL_ID}.secrets

# WORKDIR /${SCEWL_ID}.secrets

RUN echo $(awk -v min=0 -v max=255 'BEGIN{srand(); print int(min+rand()*(max-min+1))}') > data.txt
RUN cat data.txt
