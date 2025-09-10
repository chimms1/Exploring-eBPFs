
docker build -t my-ssh-image .

docker run -d -p 2222:22 --name my-ssh-container my-ssh-image


ssh -p 2222 myuser@localhost