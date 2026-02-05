* The EVCL method is implemented using a Python socket programming environment for communication between the cloud server and the edge server. Primarily, 4 very basic modules will be used for executing the data integrity verification operation 

## Working Modules

1.  **Cloud Server (CS)**: The Functionalities_CS.py consists of all the operations of CS in the backend. The CS.py is the main file for the simulation of CS operation, including sending challenges, receiving responses, and integrity verification. 
2.  **Edge Server (ES)**: Similarly, the Functionalities_ES.py consists of all the operations of ES in the backend. The ES.py for the simulation of including receiving challenges, generating an integrity proof, and sending it back to the CS. 

To execute the verification process, first run the CS.py and then ES.py. Each ES.py file will represent one individual ES.  
