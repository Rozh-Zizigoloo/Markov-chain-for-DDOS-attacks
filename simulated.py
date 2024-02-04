import numpy as np
import random
import time 

# 1. Definition of devices in the network
devices = {
    "device_1": 1,
    "device_2": 2,
    "device_3": 3,
    "device_4": 4,
    "device_5": 5,
    "device_6": 6,
    "device_7": 7,
    "device_8": 8,
    "device_9": 9,
    "device_10": 10,
    
}

# 2. Definition of thresholds
thresholds = {
    "read": {
        "safe": 10,
        "suspicious": 30,
        "malicious": 50,
    },
    "update": {
        "safe": 5,
        "suspicious": 10,
        "malicious": 25,
    },
    "delete": {
        "safe": 3,
        "suspicious": 6,
        "malicious": 15,
    },
}

# 3. Define the report function
def generate_report(device_id, activity, subactivity, number_of_activities):
    return {
        "report_id": random.randint(1, 1000),
        "number_of_activities": number_of_activities,
        "activity": activity,
        "subactivity": subactivity,
        "device_id": device_id,
    }

# 4. Simulation function
def simulate():
    reports =[]
    # Current status of devices
    device_states = {device_id: "safe" for device_id in devices}
    # Simulation for 100 reports
    i=0
    for _ in range(3):
        i+=1
        report = generate_report(
           random.choice(list(devices.keys())),
           random.choice(["read", "update", "delete"]),
           random.choice(["safe", "suspicious", "malicious"]),
           random.randint(1, 60),
        )
        print(f"report {i} is :")
        print("report id : ",report["report_id"],"\n","number of activities : ",report["number_of_activities"],"\n","activity : ",report["activity"],"\n","subactivity : ",report["subactivity"],"\n","device id : ",report["device_id"],"\n")
        reports.append(report)
        #print(reports)
        # Checking the current status of the device
        device_id = report["device_id"]
        activity = report["activity"]
        subactivity = report["subactivity"]
        number_of_activities = report["number_of_activities"]
        device_states[device_id]=report["subactivity"]
        print(device_states[device_id])
        current_state = device_states[device_id]

        # 4.1. Compare activities and thresholds
        if activity == "read":
            print(f"the activity of {device_id} are read mode")
            if subactivity == "safe": 
                 if number_of_activities <= thresholds["read"]["safe"]:
                      # 4.1.1. In safe mode
                      pass
                      print(f"{device_id} becuase thresholds in {subactivity} is less than {number_of_activities}","\n" ,f"the {device_id} stay in safe mode")
                      print(f"devices state at this moment : {device_states}")
            elif subactivity == "suspicious": 
                 if number_of_activities <= thresholds["read"]["suspicious"]:
                      # # 4.1.2. in suspicious
                     state1=device_states[device_id]
                     print(f"{device_id} goes from {state1}")
                     if device_id in devices:
                         device_states[device_id] = "suspicious_benign"
                     else:
                         device_states[device_id] = "suspicious_malicious"
                     state2=device_states[device_id]
                     print(f"to {state2}")
                     print(f"devices state at this moment : {device_states}")

                     if device_states[device_id] in ["suspicious_benign", "suspicious_malicious"]:
                         # 4.2.1. enter observation mode
                         observation_start_time = time.time()
                         observed_activities = []
                         while time.time() - observation_start_time <= 30:
                         # get new reports
                          new_reports = [
                              report for report in reports if report["device_id"] == device_id
                          ]
                         print("all reports were saved for observation state :")
                         for report in new_reports:
                             print(report["report_id"], "\n", report["number_of_activities"], "\n", report["activity"], "\n", report["subactivity"], "\n", report["device_id"], "\n")


                     for new_report in new_reports:
                         observed_activities.append(new_report["number_of_activities"])
                     average_activity = np.mean(observed_activities)
                     print(f"average_activity is {average_activity}")
            
                     if average_activity > thresholds["read"]["suspicious"] / 2:
                         # 4.2.2. enter stop mode
                         th1=thresholds["read"]["suspicious"]
                         print(f"After 30 sec observation for the {device_id}, because {average_activity} is more than half of the {th1} ","\n",f" the {device_id} goes to") 
                         device_states[device_id] = "stopped"
                         if device_id in devices: 
                           del devices[device_id]
                         sate3=device_states[device_id]
                         print(f"{sate3} and delete form devices")
                         print(devices)
                         print(f"devices state at this moment : {device_states}")
                     else:
                         # 4.2.3. Return to safe mode
                         print(f"After 1 min observation for the {device_id}, because {average_activity} is less than half of the {th1} ","\n",f" the {device_id} goes to safe mode")
                         device_states[device_id] = "safe"
                         print(f"devices state at this moment : {device_states}")
                 # ... (similar logic for "update" and "delete" activities)
            else:
                # 4.1.3. in malicious mode
                state4=device_states[device_id]
                print(state4)
                print(f"{device_id} goes from {state4}")
                if device_id in devices:
                    device_states[device_id] = "malicious_benign"
                else:
                    device_states[device_id] = "malicious_dangerous"
                state5=device_states[device_id]
                print(f"to {state5}")
                
                 # 4.3. Malicious mode check
                  # 4.3.1. enter stop mode
                print(f"the {device_id} went to {state5},So simulated program detects {device_id} is malicious and going to ")
                device_states[device_id] = "stopped"
                if device_id in devices: 
                    del devices[device_id]
                print(f"stop mode   and delete form devices")
                print(devices)
                print(f"devices state at this moment : {device_states}")
        elif activity == "update":
           print(f"the activity of {device_id} are update mode")
           if subactivity == "safe": 
                 if number_of_activities <= thresholds["update"]["safe"]:
                      # 4.1.1. In safe mode
                      pass
                      print(f"{device_id} becuase thresholds in {subactivity} is less than {number_of_activities}","\n" ,f"the {device_id} stay in safe mode")
                      print(f"devices state at this moment : {device_states}")
           elif subactivity == "suspicious": 
                 if number_of_activities <= thresholds["update"]["suspicious"]:
                      # # 4.1.2. in suspicious
                     state1=device_states[device_id]
                     print(f"{device_id} goes from {state1}")
                     if device_id in devices:
                         device_states[device_id] = "suspicious_benign"
                     else:
                         device_states[device_id] = "suspicious_malicious"
                     state2=device_states[device_id]
                     print(f"to {state2}")
                     print(f"devices state at this moment : {device_states}")

                     if device_states[device_id] in ["suspicious_benign", "suspicious_malicious"]:
                         # 4.2.1. enter observation mode
                         observation_start_time = time.time()
                         observed_activities = []
                         while time.time() - observation_start_time <= 30:
                         # get new reports
                          new_reports = [
                              report for report in reports if report["device_id"] == device_id
                          ]
                         print("all reports were saved for observation state :")
                         for report in new_reports:
                             print(report["report_id"], "\n", report["number_of_activities"], "\n", report["activity"], "\n", report["subactivity"], "\n", report["device_id"], "\n")


                     for new_report in new_reports:
                         observed_activities.append(new_report["number_of_activities"])
                     average_activity = np.mean(observed_activities)
                     print(f"average_activity is {average_activity}")
            
                     if average_activity > thresholds["read"]["suspicious"] / 2:
                         # 4.2.2. enter stop mode
                         th1=thresholds["read"]["suspicious"]
                         print(f"After 30 sec observation for the {device_id}, because {average_activity} is more than half of the {th1} ","\n",f" the {device_id} goes to") 
                         device_states[device_id] = "stopped"
                         if device_id in devices: 
                           del devices[device_id]
                         sate3=device_states[device_id]
                         print(f"{sate3} and delete form devices")
                         print(devices)
                         print(f"devices state at this moment : {device_states}")
                     else:
                         # 4.2.3. Return to safe mode
                         print(f"After 1 min observation for the {device_id}, because {average_activity} is less than half of the {th1} ","\n",f" the {device_id} goes to safe mode")
                         device_states[device_id] = "safe"
                         print(f"devices state at this moment : {device_states}")
                 # ... (similar logic for "update" and "delete" activities)
           else:
                # 4.1.3. in malicious mode
                state4=device_states[device_id]
                print(state4)
                print(f"{device_id} goes from {state4}")
                if device_id in devices:
                    device_states[device_id] = "malicious_benign"
                else:
                    device_states[device_id] = "malicious_dangerous"
                state5=device_states[device_id]
                print(f"to {state5}")
                
                 # 4.3. Malicious mode check
                  # 4.3.1. enter stop mode
                print(f"the {device_id} went to {state5},So simulated program detects {device_id} is malicious and going to ")
                device_states[device_id] = "stopped"
                if device_id in devices: 
                    del devices[device_id]
                print(f"stop mode   and delete form devices")
                print(devices)
                print(f"devices state at this moment : {device_states}")
        else:
            print(f"the activity of {device_id} are delete mode")
            if subactivity == "safe": 
                 if number_of_activities <= thresholds["delete"]["safe"]:
                      # 4.1.1. In safe mode
                      pass
                      print(f"{device_id} becuase thresholds in {subactivity} is less than {number_of_activities}","\n" ,f"the {device_id} stay in safe mode")
                      print(f"devices state at this moment : {device_states}")
            elif subactivity == "suspicious": 
                 if number_of_activities <= thresholds["delete"]["suspicious"]:
                      # # 4.1.2. in suspicious
                     state1=device_states[device_id]
                     print(f"{device_id} goes from {state1}")
                     if device_id in devices:
                         device_states[device_id] = "suspicious_benign"
                     else:
                         device_states[device_id] = "suspicious_malicious"
                     state2=device_states[device_id]
                     print(f"to {state2}")
                     print(f"devices state at this moment : {device_states}")

                     if device_states[device_id] in ["suspicious_benign", "suspicious_malicious"]:
                         # 4.2.1. enter observation mode
                         observation_start_time = time.time()
                         observed_activities = []
                         while time.time() - observation_start_time <= 30:
                         # get new reports
                          new_reports = [
                              report for report in reports if report["device_id"] == device_id
                          ]
                         print("all reports were saved for observation state :")
                         for report in new_reports:
                             print(report["report_id"], "\n", report["number_of_activities"], "\n", report["activity"], "\n", report["subactivity"], "\n", report["device_id"], "\n")


                     for new_report in new_reports:
                         observed_activities.append(new_report["number_of_activities"])
                     average_activity = np.mean(observed_activities)
                     print(f"average_activity is {average_activity}")
            
                     if average_activity > thresholds["read"]["suspicious"] / 2:
                         # 4.2.2. enter stop mode
                         th1=thresholds["read"]["suspicious"]
                         print(f"After 30 sec observation for the {device_id}, because {average_activity} is more than half of the {th1} ","\n",f" the {device_id} goes to") 
                         device_states[device_id] = "stopped"
                         if device_id in devices: 
                           del devices[device_id]
                         sate3=device_states[device_id]
                         print(f"{sate3} and delete form devices")
                         print(devices)
                         print(f"devices state at this moment : {device_states}")
                     else:
                         # 4.2.3. Return to safe mode
                         print(f"After 1 min observation for the {device_id}, because {average_activity} is less than half of the {th1} ","\n",f" the {device_id} goes to safe mode")
                         device_states[device_id] = "safe"
                         print(f"devices state at this moment : {device_states}")
                 # ... (similar logic for "update" and "delete" activities)
            else:
                # 4.1.3. in malicious mode
                state4=device_states[device_id]
                print(state4)
                print(f"{device_id} goes from {state4}")
                if device_id in devices:
                    device_states[device_id] = "malicious_benign"
                else:
                    device_states[device_id] = "malicious_dangerous"
                state5=device_states[device_id]
                print(f"to {state5}")
                
                 # 4.3. Malicious mode check
                  # 4.3.1. enter stop mode
                print(f"the {device_id} went to {state5},So simulated program detects {device_id} is malicious and going to ")
                device_states[device_id] = "stopped"
                if device_id in devices: 
                    del devices[device_id]
                print(f"stop mode   and delete form devices")
                print(devices)
                print(f"devices state at this moment : {device_states}")
    print(f" the last update of devices state is ","\n",f"{device_states}")


# 5. Run
simulate()
