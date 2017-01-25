FROM debian:latest

RUN apt-get -y update
RUN apt-get install -y curl python python-pip git
RUN curl https://sdk.cloud.google.com | bash

RUN pip install Flask pyopenssl
RUN git clone https://github.com/salrashid123/gce_metadata_server.git

WORKDIR /gce_metadata_server
ENV PATH /root/google-cloud-sdk/bin/:$PATH
EXPOSE 80 8080
RUN gcloud config set --installation component_manager/disable_update_check true
VOLUME ["/root/.config"]
#ENTRYPOINT ["python", "gce_metadata_server.py"]
