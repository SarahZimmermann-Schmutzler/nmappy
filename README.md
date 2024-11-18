# NMAPPY

The program scans ports and indicates which of the scanned ports is open or closed. For the first 100 ports to scan, it is also specified which application is running on the port.  
This is a lightweight version of the known <a href="https://nmap.org/">**Nmap**</a> - tool.  

The program was created as part of my training at the Developer Academy and is used exclusively for teaching purposes.  

It was coded on **Windows 10** using **VSCode** as code editor.

## Table of Contents
1. <a href="#technologies">Technologies</a>  
2. <a href="#features">Features</a>  
3. <a href="#getting-started">Getting Started</a>  
4. <a href="#usage">Usage</a>  
5. <a href="#additional-notes">Additional Notes</a>  

## Technologies
* **Python** 3.12.2
    * **argparse, socket, threading, queue** (modules from standard library) 

## Features
The following table shows which functions **Nmappy** supports:  

| Flag | Description | Required |
| ---- | ----------- | -------- |
| -h <br> --help | Get a list of the available options | no |
| target | Target IP or DNS address | positional argument |
| -p | Use it to scan all ports. Use it with --min and --max to specify a range. | yes |
| --min | Minimum port number to scan <br> default: 1 | no |
| --max | Maximum port number to scan <br> default: 65535 | no |

**Flow of the Function**
- The program resolves the target hostname or DNS address to an IP address, if necessary.
- It calls the `threaded_port_scan()`-function to perform a multithreaded port scan within the specified port range:
    - The number of the opened threads depends on the given port range, but 100 threads are the maximun.
    - For the first 100 ports of the given port-range the running service is identified by sending protocol-specific probes. 
- The output is a list of the open ports and services.

## Getting Started
0) <a href="https://docs.github.com/de/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo">Fork</a> the project to your namespace, if you want to make changes or open a <a href="https://docs.github.com/de/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests">Pull Request</a>.
1) <a href="https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository">Clone</a> the project to your platform if you just want to use the program.
2) In this case there are no dependencies to install. Every used module is part of Python's standard library.

## Usage
- Make sure you are in the folder where you cloned **Nmappy** into.  

- Help! What options does the program support!?  
    `python nmappy.py -h`  
    or  
    `python nmappy.py --help`  

- To scan all ports on the target server use this command:  
    `python nmappy.py [server address] -p` 
    - <ins>Example</ins>: Scan all ports on MyServer.de:  
    `python nmappy.py MyServer.de -p`
    
- To scan ports in a defined range on the server you need this command:  
    `python nmappy.py [server address] -p --min [number; default: 1] --max [number; default 65535]`
    - - <ins>Example</ins>: Scan the ports 10 to 100 on the server with the IP-Address 123.4.5.6:  
    `python nmappy.py 123.4.5.6 -p --min 10 --max 100`

- The programm lists you the open ports in the terminal. In addition the running service for the first 100 ports are identified.
    - For the example above the output could look like this:
    
    ```
    Port 53 is open (Service: Unknown)
    Port 21 is open (Service: FTP)
    Port 22 is open (Service: SSH)
    Port 80 is open (Service: HTTP)
    Port 23 is open (Service: Unknown)
    Port 25 is open (Service: FTP)
    ```

## Additional Notes
**Threading** enables multithreading, i.e. h. the parallel execution of tasks within a process. It provides an API to create, control and synchronize multiple threads.  
- Examples: executing functions in separate threads, processing tasks in parallel, synchronizing with locks..  
  
The **argparse** module is used to parse (read) command line arguments in Python programs. It allows to define arguments and options that can be passed to the program when starting it from the command line. These are then processed and are available in the program as variables.  
  
**Socket** enables communication over networks. It provides an API for creating and using sockets, the basis for many network protocols such as TCP and UDP.  
- Examples: creating connections to servers, receiving and sending data via network protocols.
  
The **queue** module provides a thread-safe queue that can be used in multithreaded environments. Threads can add or remove items from the queue without causing data inconsistencies.  
  
**ChatGPT** was involved in the creation of the program (Debugging, Prompt Engineering etc.).  
  
I use **Google Translate** for translations from German into English.