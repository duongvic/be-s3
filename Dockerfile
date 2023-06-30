FROM centos:7

WORKDIR /s3-be

RUN yum clean all && rm -rf /var/cache/yum/
RUN yum -y install epel-release

COPY . .
## copy ceph rbd rados version 15.2.11
COPY ./app/config/ceph.repo /etc/yum.repos.d/

#RUN yum -y install ceph-common zip unzip git python3 python3-devel gcc gcc-c++ make libpqxx libpqxx-devel supervisor librados-devel librbd-devel
RUN yum -y install ceph-common zip unzip git python3 python3-devel gcc gcc-c++ make libpqxx libpqxx-devel
RUN yum -y install openldap-devel

RUN pip3 install -r requirements.txt
RUN pip3 install git+https://khanhct:o1WuT9jzav6X-Yu_N7vy@git.fptcompute.com.vn/portal/foxcloud.git@tuantd#egg=foxcloud
RUN pip3 install pyOpenSSL==21.0.0

ENV PYTHONPATH /s3-be
RUN mkdir -p /var/log/s3-be-api
# CMD ["python3", "./app/api/api.py"]
CMD ["python3", "app/api/api.py"]

# TUTORIAL RUN
# docker build -t s3-be:v1 -f Dockerfile .
# docker rmi -f s3-be:v1

# TEST
# docker run -it s3-be:v1 bash
# docker run -p 5000:5000 s3-be:v1
# docker run -d -p 5000:5000 s3-be:v1
# docker rm -f $(docker ps -a -q)
