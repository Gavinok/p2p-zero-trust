# Setup

```bash
docker-compose build
docker-compose up
```
get the container ids with

```bash
docker ps
```
NOTE that each container has it's IP appended to it's name 

Then to connect to a container run

```bash
docker exec -it <containerID> /bin/bash
```

To check that they can ping back and forth install the programs
`curl`, and `netcat` on both containers.


Next on one container run

```bash
nc -l <IP-of-other-container> 444
```

Then on the other container run

```bash
curl -X "Yooooo" <IP-of-other-container>:444
```

You should see a message appear on the first container running netcat
with the corresponding HTTP request.
