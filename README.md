# Secure Aggregation

This is an unofficial implementation of Secure Aggregation Protocol. The details of the protocol can be found in the original paper: [(CCS'17) Practical Secure Aggregation for Privacy-Preserving Machine Learning](https://dl.acm.org/doi/abs/10.1145/3133956.3133982).

## Usage

There are two ways to use the Secure Aggregation Protocol.

### Docker
---

This is the recommended option, as all entities are independent containers. That is, a real federated learning scenario is simulated in this way.

- Pull base image:
```
$ docker pull chenjunbao/secureaggregation
```

- Build docker images for each entity:
```
$ git clone https://github.com/chen-junbao/secureaggregation.git
$ cd secureaggregation/docker
$ ./scripts/build.sh
```

- Simulate 100 users and set the waiting time and iteration to 60 seconds and 20, respectively:
```
$ ./start.sh -u 100 -t 60 -i 20
```

### Single Machine
---

- Install python libraries:

```
$ git clone https://github.com/chen-junbao/secureaggregation.git
$ cd secureaggregation
$ pip install -r requirements.txt
$ pip install git+https://github.com/blockstack/secret-sharing

$ python main.py -h
```

- Simulate 100 users and set the waiting time to 300 seconds:
```
$ python main.py -u 100 -t 300
```