FROM python:2.7-slim
ADD . /app
WORKDIR /app
RUN pip install Flask dnspython oauth2client google-api-python-client httplib2 google-cloud 
EXPOSE 8080
ENTRYPOINT ["python", "main.py"]
