[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/PhilippMundhenk/IVNS/blob/master/LICENSE)

# IVNS
The In-Vehicle Network Simulator (IVNS) is a Python-based simulator, allowing to evaluate parameterized software models of automotive networks for timing and security, among others.

The design and implementation of this work has been performed by **Artur Mrowca**.

## Support
This work has been created in TUM CREATE and was financially supported by the Singapore National Research Foundation under its Campus for Research Excellence and Technological Enterprise (CREATE) program.

## Description

This simulator simulates any bus topology within any network on a timing bases. It allows to define 
the number and behaviour of various ECUs by reimplementing them, to send certain message flows and to 
exploit the layered structure of each ECU to test the timing behaviour of security protocols in
different scenarios.
E.g. LASAN, TESLA or TLS
It is also highly extensible as it allows to interchange layers within the ECUs, implement any bus
type desired, create and test any topology, define result outputs by using exising or self implemented 
plugins, create own GUI plugins and define the timing behaviour from an extensible database.
In order to use this simulation simpy needs to be downloaded and installed to your python version. Also the 
Python version 2.7 was used in this implementation.


This guide quickly introduces the main building bricks of this network simulator and how to use it 
for an individual application. 
In its current shape the simulation consists out of ECUs, buses and gateways that can be 
interconnected. Also the ECUs themselves consist of layers including a physical, data link and
a transport layer, as well as a communication layer and a application layer.


## 1. Structure of the IVNS repository

The uploaded project is structured into 3 subprojects.

	- ECUSimulation:  This project contains the main building bricks of the network including
			  various ECUs, gateways and a CAN Bus. New components and layers can be added
			  to those components as desired.
			  Additionally the API that is used to run the simulation is found in this
			  folder.
	- ECUInteraction: This project contains the GUI that is connected to the simulation. It is
			  used to visualize events within the simulation. It receives information from
			  monitoring points of the simulation which pass information to a general
			  pipline from which the GUI receives its simulation information.
	- TestSimulation: This folder contains an example usage of the API and how to use it
			  to generate a running simulation using the building bricks given in the
			  ECUSimulation.

## 2. ECUSimulation - Basic Components

As indicated below, the simulator consists of a database, configuration files and the simulation core.
To achieve realisitic results for the timing behaviour of security protocols, this simulator offers the
possibility to read out latencies from encryption, decryption, signing and verification from a database
depending on the size of the message that is to be processed and the type of algorithm that is used. This
includes e.g. RSA or AES encryption with various keys (512 to 2048 bit for RSA and 128 to 256 bit for AES).
The database was measured on a STM32 microcontroller and is stored in \ECUSimulation\config\data\measurements.db.
Furthermore to configure ECUs, gateways and buses either the API can be used or the project.ini and timings.ini and 
can_ids.ini file can be used which are located in IVNS\ECUSimulation\config\data. This will be demonstrated in the 
walkthrough in a later section.

	Database with 			Configuration files - 
	times measured with 		project, timings, busIds	
	an STM32 Microcontroller		
		|								|	
		---------------------------------
			       |
			ECUSimulation Core
			       |
			      API
			       |
			    Python 
			  Application 
			  w or w/o GUI

An easy way to get started is to download the ECUSimulation, ECUInteraction and TestSimulation project and to open it in Eclipse with 
PyDev on it. By then running the python file main_lwa_preset.py in TestSimulation the setup of a simulation is demonstrated.


## 3. Walkthroughs

For tutorials and how to use the simulator checkout the wiki at: https://github.com/arturmrowca/IVNS/wiki





