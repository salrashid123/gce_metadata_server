FROM google/cloud-sdk
RUN apt-get -y update
RUN apt-get install -y curl python python-pip python-dev build-essential git
RUN pip install Flask
RUN git clone https://github.com/salrashid123/gce_metadata_server.git
WORKDIR /gce_metadata_server
ENTRYPOINT ["python", "gce_metadata_server.py"]
