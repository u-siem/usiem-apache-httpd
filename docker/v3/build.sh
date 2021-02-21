docker stop usiem-apache2-test
docker rm usiem-apache2-test
docker build -t usiem-apache2 .
docker run -dit --name usiem-apache2-test -p 8080:80 usiem-apache2
docker exec -it $(docker ps -q) /bin/bash