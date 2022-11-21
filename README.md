# Setup

First build the project

Ensure you have https://github.com/roswell/roswell installed and the `ros` executable in your path

Then you can build the project by running

```bash
make
```

This will compile the executable in `client/p2p-test/p2p` and
copy it into the `peer1` and `peer1` directories.

Next you can run the following commands to start the containers

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
docker exec -it <containerID> bash
```

Next on one container run

```bash
./p2p server <IP-OF-THIS-CONTAINER> -p 9000
```

Then on the other container run

```bash
./p2p client <IP-OF-OTHER-CONTAINER> -p 9000
```

You should see the container running the server begin to print
`hello`.

Long term we will have these run from the start but for now this makes
debugging much easier.


## Cleanup

If you want to wipe all the p2p executable run 
```bash
make clean
```
