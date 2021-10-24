## EncoderDecoder
1) Generate RSA key pair and shards the private key into k of n shares
using Shamir secret sharing algorithm. 
2) The app should be able to re-create the private key if 2
of n shares are presented.
3) The program should write the public key to a text file called Public.TXT, and the private key shards to text files called Shard[k].TXT.


## BUILD INSTRUCTIONS
1)Install jdk 11
2) Install maven
3) From parent directory  run  "mvn clean dependency:copy-dependencies package"
4) You can run test using "mvn test"
5) Go to target folder inside parent directory to run jar
Run "java -jar encode-0.0.1-SNAPSHOT.jar  arg1 arg2 arg3"
Arg1: name of string to be encoded
Arg2: n
Arg3: k(2 in this case)

Example:java -jar encode-0.0.1-SNAPSHOT.jar  tester 5 2
 


