#+OPTIONS: toc:nil

Warning: there still is an enormous list of issues with =beerocks_analyzer=, and only the connection map currently works. This README will walk you through installing dependencies and displaying the connection map.


* Prerequisites
You need to install a few python packages before using it.
This readme will walk you through installing them in a =virtualenv=.
Using a virtualenv allows to install the dependencies in a local directory, which avoids messing with the local Python installation.

You only need to create the =venv= once. Later on you just need to activate the =venv= to be able to use the application.

** Create a virtualenv to use the application
 #+BEGIN_SRC sh
 python3 -m venv venv
 #+END_SRC

*** Activate the environment
 #+BEGIN_SRC sh
 source venv/bin/activate
 #+END_SRC

 Your prompt should now have "venv" appended to it.

 You can deactivate it by running ~deactivate~.

*** Install all the required package inside the virtualenv
 #+BEGIN_SRC sh
 pip install -r requirements.txt
 #+END_SRC

* Running the application
First make sure you activate the =venv=, or that you installed the required packages.

The analyzer currently connects to a running controller, then from there opens a socket back to the analyzer.
This means that you need to have access to the controller (locally, via docker, or via ssh) but that the controller also needs to be able to access the device on which the analyzer is running.

** Using a controller running locally
You need to give the path to beerock's binaries (change ~BIN_PATH~ according to your installation):
#+BEGIN_SRC sh
BIN_PATH="/home/$USER/prplmesh_root/build/install/bin/beerocks_cli"
python beerocks_analyzer.py -map -bin_path="$BIN_PATH" -docker_container=gateway
#+END_SRC

** Using a controller in a local docker container
You need to give the path to beerock's binaries (change ~BIN_PATH~ according to your installation), the gateway IP from the container point of view (change ~MY_IP~, it probably starts with 172), and the container name:
#+BEGIN_SRC sh
BIN_PATH="/home/$USER/prplmesh_root/build/install/bin/beerocks_cli"
MY_IP=172.19.0.1
DOCKER_CONTAINER="gateway"
python beerocks_analyzer.py -map -bin_path="$BIN_PATH" -docker_container="$DOCKER_CONTAINER" -my_ip="$MY_IP"
#+END_SRC

** Using a remote controller over SSH
You first need to have a private key (one that can connect to the remote device) registered in your local agent, so that you don't get asked for a password.

If you don't have one running, you can run an agent by doing ~eval `ssh-agent -s`~.
To register your key, just do ~ssh-add~.

To run the analyzer, you then need to give the path to beerock's binaries (change ~BIN_PATH~ according to your installation) and the target IP:
#+BEGIN_SRC sh
BIN_PATH="/home/$USER/prplmesh_root/build/install/bin/beerocks_cli"
TARGET_IP=192.168.1.1
python beerocks_analyzer.py -map -bin_path="$BIN_PATH" -gw_ip="$TARGET_IP"
#+END_SRC
