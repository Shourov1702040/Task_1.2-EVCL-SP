* The EVCL method is implemented using a Python socket programming environment for communication between the cloud server and the edge server. Primarily, 4 modules will be used for executing the data integrity verification operation 

## Technical Workflow

1.  **System Setup:** Parameters are established at the Cloud Server level.
2.  **Challenge Issuance:** The system generates additional info for Edge Servers (ESs) to trigger a verification cycle.
3.  **Proof Generation:** Edge Servers respond with a proof tag and a localization key.
4.  **Audit & Response:** The Cloud Server validates the response; if the data is compromised, it identifies the specific corrupted blocks immediately.

## 🏁 Conclusion

This framework provides a scalable, secure method for managing data across distributed networks. By utilizing mathematical proofs for integrity, it ensures that data remains untampered and verifiable regardless of its physical storage location.
