# lambda-persistency-poc
See [Twistlock Labs](https://www.twistlock.com/labs-blog/gaining-persistency-vulnerable-lambdas/) for more info.
 
A repository containing two POCs of an attacker gaining persistency on a vulnerable AWS python Lambda.
 
Both POCs compromise a Lambda instance by replacing the bootstrap process (the runtime) with a malicious version.
 
 
- **poc** - a POC relying on an RCE that executes code in the context of the vulnerable function
- **exteranl_process_poc** - a POC relying on an RCE that executes code in an external process 
