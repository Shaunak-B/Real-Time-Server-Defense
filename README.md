# Real Time server attack detection.
	
**Problem Statement**: Identify what factors are involved in suspicious sessions in a server and also build a classification model to predict an attack during a session.

**Abstract**: Network security is becoming increasingly relevant with the enormous growth of computer network use and the enormous increase in the number of applications running on top of it. All computer systems suffer from security flaws that are technically difficult to overcome by manufacturers and economically expensive.The position of Intrusion Detection Systems (IDSs), as special purpose devices for detecting network anomalies and attacks, is therefore becoming increasingly important. For a long time, research in the intrusion detection area has concentrated mainly on anomaly-based and misuse-based detection techniques. While detection based on misuse is generally favored in commercial products because of its predictability and high precision, in academic research.Due to its theoretical potential for resolving novel attacks, anomaly detection is usually conceived as a more efficient tool. There is no evidence of using machine learning based anomaly detection methods when we look at the state of the art IDS solutions and commercial resources, and practitioners still claim that it is an immature technology.

**Approach**: To use a machine learning model to detect an ongoing attack by using factors like size of the data transferred in single connection, number of wrong fragments in the connection, number of failed logins and different time related traffic features. 

**Persona**: Enterprise companies that value their software and want to protect it in real-time..

**Dataset**: http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html

**High Level Architecture**:

![image](https://user-images.githubusercontent.com/34078992/117555622-8cebd680-b015-11eb-9e5e-4007534f26d3.png)
![image](https://user-images.githubusercontent.com/34078992/110900239-4e58ca80-82b7-11eb-9d57-9f5415f4bac6.png)
