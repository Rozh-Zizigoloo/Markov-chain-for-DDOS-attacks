# Markov chain for detection DDOS attacks ⛓️
The main topic of this research is to investigate the potential of Markov chain models to predict and prevent DDoS attacks in 5G-based IoT networks. By analyzing past attack patterns and device behavior, these models can provide insight into potential vulnerabilities and enable proactive security measures.

## Tools ⚙

- python

# Project implementation 🕹️
**A secure 5G-capable IoT architecture: an overview**
Figure 1 shows a hierarchical 5G-capable IoT security architecture based on distributed multi-access edge computing (MEC). This architecture uses three layers:
• Access layer: It includes the physical devices that collect and transmit data to the MEC layer.
• MEC layer: processes and analyzes the collected data.
• Cloud layer: manages massive data.

![load](https://github.com/Rozh-Zizigoloo/Markov-chain-for-DDOS-attacks/blob/main/images/Screenshot%202024-02-04%20201305.png)

## main point
Each device performs three activities:
•	**Read**
•	**Update**
•	**Delete**
A device can create an attack by maliciously performing one of these basic activities. For example, a DDoS attack occurs when a device overloads the system with read activity.
Based on this, DDOS attacks are divided into two categories (dangerous and harmless).
Harmless attack includes attacks that occur on behalf of devices due to improper use.
Malicious attack includes attacks directed by a malicious device.

## State space in systems efficiency evaluation 🧮

In short, the state space in this Markov model:
The state space contains 7 states for each of the read, update, and delete operations. In total, there are 21 distinct modes:

**Reading activity:**
- **Secure (A):** The number of reported activities is between 0 and TH(A).
- **Suspicious-benign reading (B1)**: The number of reported activities is between TH(A)+1 and TH(B1).
- **Suspicious-Dangerous Reading(B2)**: The number of reported activities is between TH(A)+1 and TH(B2).
- **Malicious-benign reading (C1)**: The number of activities reported from TH(B1)+1.
- **Malicious-dangerous reading (C2)**: The number of activities reported from TH(B2)+1.
- **Stop (S)**: A device can be placed in this state when the reporting activity is in the malicious (C1) or (C2) ranges.
- **Observation (Obs)**: If a device remains in one of the two modes (B1) or (B2) during the observation time, it can be placed in this mode.

 📑
```diff
- note: Update & delete activity are same as reading activity.
```
## state transition diagram (STD) 📈

![STD](https://github.com/Rozh-Zizigoloo/Markov-chain-for-DDOS-attacks/blob/main/images/1.drawio.svg)

## Simulation (simulation program code)
**1. Definition of devices in the network:** 
We create a dataset of devices and their IDs :(example 10 devices)

```
devices = {
    "device_1": 1,
    "device_2": 2,
     ...   
}
print(devices)
```
**2. Defining the threshold for each state as a TH variable, which states include:**
- safe state => TH(safe).
- suspicious state => TH(suspicious).
- malicious state => TH(malicious).
> Now, each threshold for activities (read-write-delete) is defined separately.
There are a total of 9 modes.
```
thresholds = {
    "read": {
        "safe": TH(safe),
        "suspicious": TH(suspicious),
        "malicious": TH(malicious),
    },
    "update": {
        #same
    },
    "delete": {
        #same
    },
}
```
**3. Defining the report for each state as a random function EXP():**
a dataset with these features: 
- report number 
- number of reported activities
- general activity (reading - updating - deleting)
- underlying activity (reported activities for safe mode
- malicious - suspicious)
- device id (the device that reported) is formed.
```
def generate_report(device_id, activity, subactivity, number_of_activities):
    return {
        "report_id": random.randint(1, 1000),
        "number_of_activities": number_of_activities,
        "activity": activity,
        "subactivity": subactivity,
        "device_id": device_id,
    }

```
**4. Comparing the number of reported activities and the thresholds of each mode:**
For each reported device, do the following:
- If 0 < activity reported in safe mode <= TH(safe).
- If TH(safe) < reported activity in safe mode <= TH (suspicious).
- If TH (suspicious)  < activity reported in suspicious mode.
 
```
 if activity == "read":
            print(f"the activity of {device_id} are read mode")
            if subactivity == "safe": 
                 if number_of_activities <= thresholds["read"]["safe"]:
                 ##
            elif subactivity == "suspicious":     
                 if number_of_activities <= thresholds["read"]["suspicious"]:
                 ##
            else:
                 ##
 elif activity == "update":
           print(f"the activity of {device_id} are update mode")
           if subactivity == "safe": 
                 if number_of_activities <= thresholds["update"]["safe"]:
                 ##
           elif subactivity == "suspicious": 
                 if number_of_activities <= thresholds["update"]["suspicious"]:
                 ##
            else:
                 ##
else:
           print(f"the activity of {device_id} are delete mode")
           if subactivity == "safe": 
                 if number_of_activities <= thresholds["delete"]["safe"]:
                 ##
           elif subactivity == "suspicious": 
                 if number_of_activities <= thresholds["delete"]["suspicious"]:
                 ##
            else:
                 ##
```

## result 🎬
A simulation with three random reports:

![result](https://github.com/Rozh-Zizigoloo/Markov-chain-for-DDOS-attacks/blob/main/images/hhhh.png)

## References📑

- [essay 1](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3898954)
- [essay 2](https://www.researchgate.net/publication/322407312_Detection_techniques_of_DDoS_attacks_A_survey)
- [essay 3](https://dl.acm.org/doi/abs/10.1007/s11276-019-02043-1)
