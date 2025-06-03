# DDoS-Detection-using-ML
# DDoS Detection and Mitigation Using SDN with Mininet and Machine Learning

This project implements a real-time detection and mitigation system for Distributed Denial of Service (DDoS) attacks in Software-Defined Networking (SDN) environments using machine learning and Mininet.

## 📌 Project Title
**DDoS Detection and Mitigation Using SDN with Mininet and Machine Learning**

## 👥 Team Members
- Varshitha Thilak Kumar – CB.SC.U4AIE23258  
- Siri Sanjana S – CB.SC.U4AIE23249  
- Shreya Arun – CB.SC.U4AIE23253  
- Anagha Menon – CB.SC.U4AIE23212  

## 🏫 Institution
Amrita School of Artificial Intelligence  
Amrita Vishwa Vidyapeetham, Coimbatore, Tamil Nadu, India

---

## 📖 Abstract

The system integrates Software-Defined Networking (SDN), Mininet, and machine learning to create an automated defense mechanism against DDoS attacks. Unlike many traditional models that only detect attacks, this approach also mitigates them in real time using SDN controller actions like rerouting and blocking. Machine learning classifiers, specifically Random Forest and SVM, are trained on SDN-specific traffic datasets and embedded within the SDN controller for real-time inference.

---

## 🎯 Objectives

- Build an SDN-based DDoS detection and mitigation framework using Mininet.
- Train ML models on traffic datasets to detect anomalies.
- Integrate detection and automatic mitigation within the SDN controller.
- Evaluate system performance based on accuracy, recall, precision, and false alarm rate.
- Enhance resilience and scalability of SDN networks against evolving cyber threats.

---

## 🛠️ Methodology

1. **Network Simulation**  
   - Used **Mininet** to simulate an SDN environment.
   - Deployed the **RYU Controller** for SDN control logic.
   - Normal traffic via `iperf`, attack traffic via `hping3`.

2. **Data Collection and Preprocessing**  
   - Extracted flow statistics (packet count, byte count, duration, flags, etc.).
   - Saved to `FlowStatsfile.csv`.
   - Removed irrelevant fields (e.g., IP addresses), normalized the rest.

3. **Feature Set**  
   - Examples: `flow_duration`, `packet_count`, `icmp_type`, `byte_count_per_second`, etc.
   - Total records: 27,998.

4. **Model Training**  
   - Trained **Random Forest** and **SVM**.
   - Random Forest achieved highest accuracy (99.88%).

5. **Real-Time Deployment**  
   - Embedded the best-performing model in the RYU controller.
   - Detected malicious traffic in real-time and mitigated via OpenFlow rules.

6. **Mitigation Actions**
   - Block malicious IPs.
   - Redirect traffic to honeypots.
   - Auto-adjust rules based on evolving attack patterns.

---

## 📊 Results

| Metric       | Random Forest | SVM        |
|--------------|---------------|------------|
| Accuracy     | 99.88%        | 98.50%     |
| Precision    | High          | Moderate   |
| False Alarms | Very Low      | Higher     |
| Scalability  | High          | Limited    |

- Random Forest proved more scalable and robust in high-traffic conditions.
- Real-time classification and mitigation significantly improved QoS.

---

## 📁 Dataset Overview

- **Total Records**: 27,998
- **Type**: Binary classification (0 = benign, 1 = attack)
- **Data Source**: Mininet simulations with benign and DDoS traffic
- **Attributes**: 22 flow-level features, no deep packet inspection

---

## ⚙️ System Requirements

- Python 3.x
- Mininet
- RYU Controller
- scikit-learn, pandas, numpy, joblib
- Tools: `iperf`, `hping3`

---

## 🚀 Future Enhancements

- Integrate **deep learning (CNN-LSTM)** for zero-day attacks.
- Use **distributed SDN controllers** for scalability.
- Implement **dynamic thresholding** to reduce false positives.
- Expand to include **behavioral analysis** and **application-layer data**.

---

## 📚 References

1. Sharma et al. (2023). *ML-based DoS detection in WSNs.*
2. Manso et al. (2019). *SDN-based IDS for DDoS.*
3. Mousavi & St-Hilaire (2015). *Early detection for SDN.*
4. Jia et al. (2022). *Lightweight detection using ARIMA + SVM.*
5. Singh & Jain (2024). *Survey on SDN-IoT DDoS detection.*

---

## 🛡️ Impact

This project addresses a critical gap in SDN-based security by combining detection and mitigation into a single, scalable framework. It paves the way for future research in AI-powered autonomous defense systems for modern networks.

