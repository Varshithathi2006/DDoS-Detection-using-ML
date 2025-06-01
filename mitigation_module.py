from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switchm
from datetime import datetime

import pickle
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
import ipaddress

# Import the traffic visualization module
from traffic_visualization import TrafficVisualization

class SimpleMonitor13(switchm.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Add mitigation state variables
        self.mitigation = 0
        # Dict to store attack-specific information, key = victim_ip
        self.active_attacks = {}
        self.attack_history = []
        self.mitigation_log = []
        
        # Initialize traffic visualization module
        self.traffic_viz = TrafficVisualization()

        start = datetime.now()
        self.logger.info("Starting Random Forest model training...")
        
        self.flow_training()
        
        end = datetime.now()
        self.logger.info("Training time: %s", (end-start))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.logger.debug("Monitoring cycle started")
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            try:
                self.flow_predict()
                
                # Check for ended attacks that need cleanup
                self.check_ended_attacks()
            except Exception as e:
                self.logger.error("Error in monitoring cycle: %s", e)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try:
            timestamp = datetime.now()
            timestamp = timestamp.timestamp()

            file0 = open("PredictFlowStatsfile.csv", "w")
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            body = ev.msg.body
            icmp_code = -1
            icmp_type = -1
            tp_src = 0
            tp_dst = 0

            for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
                (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
            
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']
                ip_proto = stat.match['ip_proto']
                
                if stat.match['ip_proto'] == 1:
                    icmp_code = stat.match['icmpv4_code']
                    icmp_type = stat.match['icmpv4_type']
                    
                elif stat.match['ip_proto'] == 6:
                    tp_src = stat.match['tcp_src']
                    tp_dst = stat.match['tcp_dst']

                elif stat.match['ip_proto'] == 17:
                    tp_src = stat.match['udp_src']
                    tp_dst = stat.match['udp_dst']

                # Create flow ID preserving the original format with dots
                flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
              
                try:
                    packet_count_per_second = stat.packet_count/stat.duration_sec
                    packet_count_per_nsecond = stat.packet_count/stat.duration_nsec
                except:
                    packet_count_per_second = 0
                    packet_count_per_nsecond = 0
                    
                try:
                    byte_count_per_second = stat.byte_count/stat.duration_sec
                    byte_count_per_nsecond = stat.byte_count/stat.duration_nsec
                except:
                    byte_count_per_second = 0
                    byte_count_per_nsecond = 0
                    
                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                            stat.match['ip_proto'],icmp_code,icmp_type,
                            stat.duration_sec, stat.duration_nsec,
                            stat.idle_timeout, stat.hard_timeout,
                            stat.flags, stat.packet_count,stat.byte_count,
                            packet_count_per_second,packet_count_per_nsecond,
                            byte_count_per_second,byte_count_per_nsecond))
                
            file0.close()
        except Exception as e:
            self.logger.error("Error in flow stats handler: %s", e)

    def flow_training(self):
        try:
            self.logger.info("RandomForest Training ...")
            modelDB = 'rf_model.pkl'
            
            if os.path.exists(modelDB):
                # Load the saved model from file
                self.logger.info("File exist, loading model")        
                with open(modelDB, 'rb') as file:
                    self.flow_model = pickle.load(file)            
            else:
                self.logger.info("File does not exist, training model")

                flow_dataset = pd.read_csv('FlowStatsfile.csv')

                # Store original IP columns before modifying for training
                self.original_ip_src = flow_dataset.iloc[:, 3].copy()
                self.original_ip_dst = flow_dataset.iloc[:, 5].copy()
                
                # Remove dots for numerical processing
                flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '', regex=False)
                flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '', regex=False)
                flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '', regex=False)

                X_flow = flow_dataset.iloc[:, :-1].values
                X_flow = X_flow.astype('float64')

                y_flow = flow_dataset.iloc[:, -1].values

                X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(
                    X_flow, y_flow, test_size=0.25, random_state=0)

                # Use RandomForestClassifier instead of DecisionTree
                classifier = RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=0)
                self.flow_model = classifier.fit(X_flow_train, y_flow_train)

                y_flow_pred = self.flow_model.predict(X_flow_test)
                y_flow_pred_train = self.flow_model.predict(X_flow_train)

                with open(modelDB, 'wb') as file:
                    pickle.dump(self.flow_model, file)

                self.logger.info("------------------------------------------------------------------------------")

                self.logger.info("Confusion Matrix")
                cm = confusion_matrix(y_flow_test, y_flow_pred)
                self.logger.info(cm)

                acc = accuracy_score(y_flow_test, y_flow_pred)

                acc_train = accuracy_score(y_flow_train, y_flow_pred_train)
                self.logger.info("Training Accuracy: %s", acc_train)

                self.logger.info("Success Accuracy = {0:.2f} %".format(acc*100))
                fail = 1.0 - acc
                self.logger.info("Fail Accuracy = {0:.2f} %".format(fail*100))
                
                # Print feature importance
                feature_importance = self.flow_model.feature_importances_
                self.logger.info("Feature importance:")
                for i, importance in enumerate(feature_importance):
                    if importance > 0.01:  # Only show important features
                        self.logger.info(f"Feature {i}: {importance:.4f}")
                
                self.logger.info("------------------------------------------------------------------------------")
        except Exception as e:
            self.logger.error("Error in flow training: %s", e)

    def flow_predict(self):
        try:
            # Check if prediction file exists
            if not os.path.exists('PredictFlowStatsfile.csv'):
                self.logger.debug("No prediction file available yet")
                return
                
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
            
            # Check if file is empty (only header)
            if predict_flow_dataset.shape[0] == 0:
                self.logger.debug("Prediction file is empty")
                return
                
            self.logger.debug("Processing prediction file with %d entries", predict_flow_dataset.shape[0])

            # Store original IPs for mitigation before modifying
            original_ip_src = predict_flow_dataset.iloc[:, 3].copy()
            original_ip_dst = predict_flow_dataset.iloc[:, 5].copy()
            
            # Process data for prediction (removing dots)
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '', regex=False)
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '', regex=False)
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '', regex=False)

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = 0
            ddos_traffic = 0
            
            # Dictionary to track potential DDoS attacks by victim
            potential_attacks = {}
            
            for i in range(len(y_flow_pred)):
                if y_flow_pred[i] == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1
                    victim_ip = original_ip_dst[i]
                    attacker_ip = original_ip_src[i]
                    
                    # Track potential DDoS by victim
                    if victim_ip not in potential_attacks:
                        potential_attacks[victim_ip] = {
                            'count': 0,
                            'attackers': set()
                        }
                    
                    potential_attacks[victim_ip]['count'] += 1
                    potential_attacks[victim_ip]['attackers'].add(attacker_ip)

            self.logger.info("------------------------------------------------------------------------------")
            self.logger.info("Legitimate: %d flows, DDoS: %d flows", legitimate_traffic, ddos_traffic)
            
            # Record overall traffic metrics
            self.traffic_viz.record_traffic_metrics(
                timestamp=datetime.now(),
                legitimate_count=legitimate_traffic,
                ddos_count=ddos_traffic,
                mitigation_active=bool(self.active_attacks),
                blocked_sources_count=sum(len(attack['blocked_ips']) for attack in self.active_attacks.values()),
                flow_stats_df=predict_flow_dataset,
                victim_ips=list(potential_attacks.keys()) if potential_attacks else None
            )
            
            # Process each potential attack
            for victim_ip, attack_data in potential_attacks.items():
                attack_flow_count = attack_data['count']
                attacker_ips = attack_data['attackers']
                
                # Calculate percentage of malicious traffic for this victim
                victim_percentage = attack_flow_count / len(y_flow_pred) * 100
                attacker_count = len(attacker_ips)
                
                self.logger.info("Potential attack on %s: %d flows (%.2f%%) from %d unique sources", 
                                victim_ip, attack_flow_count, victim_percentage, attacker_count)
                
                # Check if this is a DDoS attack (threshold-based)
                # Using two criteria: percentage of total traffic and number of sources
                if victim_percentage > 15 and attacker_count >= 3:
                    if victim_ip not in self.active_attacks:
                        self.logger.info("NEW ATTACK DETECTED on %s", victim_ip)
                        # Initialize a new attack entry
                        self.active_attacks[victim_ip] = {
                            'start_time': datetime.now(),
                            'blocked_ips': set(),
                            'attacker_count': attacker_count,
                            'last_update': datetime.now(),
                            'attack_intensity': attack_flow_count
                        }
                    else:
                        # Update existing attack record
                        self.active_attacks[victim_ip]['last_update'] = datetime.now()
                        self.active_attacks[victim_ip]['attack_intensity'] = attack_flow_count
                        
                    # Apply mitigation measures for this attack
                    self.apply_mitigation(list(attacker_ips), victim_ip)
                else:
                    self.logger.debug("Traffic to %s doesn't meet DDoS criteria", victim_ip)
            
            # Generate visualizations periodically
            if len(self.traffic_viz.traffic_data['timestamps']) % 5 == 0:
                try:
                    self.logger.info("Generating traffic visualizations...")
                    viz_results = self.traffic_viz.generate_all_visualizations()
                    csv_path = self.traffic_viz.export_data_to_csv()
                    self.logger.info("Visualizations updated successfully:")
                    for viz_type, path in viz_results.items():
                        if path:
                            self.logger.info("- %s: %s", viz_type, path)
                    self.logger.info("- CSV data: %s", csv_path)
                except Exception as viz_error:
                    self.logger.error("Error generating visualizations: %s", viz_error)
            
            self.logger.info("------------------------------------------------------------------------------")
            
            # Clear the prediction file after processing
            file0 = open("PredictFlowStatsfile.csv", "w")
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            file0.close()

        except Exception as e:
            self.logger.error("Error in flow prediction: %s", e)

    def apply_mitigation(self, malicious_sources, victim_ip):
        """Apply mitigation measures to block malicious traffic for a specific victim."""
        try:
            if not malicious_sources or not victim_ip:
                self.logger.warning("No malicious sources or victim IP identified")
                return
            
            if victim_ip not in self.active_attacks:
                self.logger.error(f"Trying to mitigate non-tracked attack on {victim_ip}")
                return
                
            attack_record = self.active_attacks[victim_ip]
            
            # Log the attack details
            log_entry = {
                "timestamp": datetime.now(),
                "victim_ip": victim_ip,
                "attacker_count": len(set(malicious_sources)),
                "action": "block"
            }
            self.mitigation_log.append(log_entry)
            
            # Find new malicious IPs to block
            current_blocked = attack_record['blocked_ips']
            new_blocked = set(malicious_sources) - current_blocked
            
            if new_blocked:
                self.logger.info(f"Blocking {len(new_blocked)} new malicious sources targeting {victim_ip}")
                
                # Validate victim IP format
                try:
                    # Ensure victim_ip is a valid IPv4 address
                    ipaddress.IPv4Address(victim_ip)
                except ValueError:
                    self.logger.error(f"Invalid victim IP address: {victim_ip}")
                    return
                
                # Apply blocking rules on all datapaths
                for dp in self.datapaths.values():
                    self.logger.debug(f"Adding block rules to datapath {dp.id}")
                    ofproto = dp.ofproto
                    parser = dp.ofproto_parser
                    
                    # Add a counter for success tracking
                    success_count = 0
                    
                    for ip_idx, ip in enumerate(new_blocked):
                        try:
                            # Validate source IP format
                            ipaddress.IPv4Address(ip)
                            
                            self.logger.debug(f"Processing IP {ip_idx+1}/{len(new_blocked)}: {ip}")
                            # Create flow match for the malicious source
                            match = parser.OFPMatch(
                                eth_type=0x0800,  # IPv4
                                ipv4_src=ip,
                                ipv4_dst=victim_ip
                            )
                            
                            # Drop action by specifying empty action list
                            actions = []
                            
                            try:
                                # Add flow entry with high priority (100)
                                flow_serial_no = switchm.get_flow_number()
                                self.add_flow(dp, 100, match, actions, flow_serial_no)
                                current_blocked.add(ip)  # Add to blocked set
                                success_count += 1
                                self.logger.info(f"Blocked traffic from {ip} to {victim_ip}")
                            except Exception as e:
                                self.logger.error(f"Error adding block rule for {ip}: {e}")
                        except ValueError:
                            self.logger.error(f"Invalid source IP address: {ip}, skipping")
                            continue
                    
                    self.logger.info(f"Successfully added {success_count}/{len(new_blocked)} blocking rules for {victim_ip}")
                
                # Update attack record with new blocked IPs
                attack_record['blocked_ips'] = current_blocked
                
                # Save the mitigation log to a file
                self.save_mitigation_log()
                
                # Generate a visualization of the mitigation in progress
                try:
                    self.logger.info("Generating attack mitigation visualization...")
                    self.traffic_viz.generate_attack_specific_visualization(
                        victim_ip, 
                        len(current_blocked),
                        attack_record['start_time'],
                        f'attack_{victim_ip.replace(".", "_")}_in_progress.png'
                    )
                except Exception as viz_error:
                    self.logger.error("Error generating attack visualization: %s", viz_error)
        except Exception as e:
            self.logger.error(f"Error in apply_mitigation: {e}")

    def check_ended_attacks(self):
        """Check if any active attacks have ended and should be cleaned up."""
        try:
            current_time = datetime.now()
            attacks_to_end = []
            
            for victim_ip, attack_data in self.active_attacks.items():
                # If no activity for this attack in the last 3 monitoring cycles (30 seconds)
                if (current_time - attack_data['last_update']).total_seconds() > 30:
                    self.logger.info(f"Attack on {victim_ip} appears to have subsided.")
                    attacks_to_end.append(victim_ip)
            
            # Process ended attacks
            for victim_ip in attacks_to_end:
                self.end_attack_mitigation(victim_ip)
                
        except Exception as e:
            self.logger.error(f"Error in check_ended_attacks: {e}")

    def end_attack_mitigation(self, victim_ip):
        """End mitigation for a specific attack that has subsided."""
        try:
            if victim_ip not in self.active_attacks:
                self.logger.error(f"Trying to end mitigation for non-existent attack: {victim_ip}")
                return
                
            attack_data = self.active_attacks[victim_ip]
            
            # Remove all blocking rules for this victim
            for dp in self.datapaths.values():
                self.logger.info(f"Removing blocking rules for {victim_ip} from datapath {dp.id}")
                self.delete_flow_by_victim(dp, victim_ip)
            
            # Calculate attack statistics
            attack_duration = datetime.now() - attack_data['start_time']
            blocked_sources = len(attack_data['blocked_ips'])
            
            # Log the end of mitigation
            log_entry = {
                "timestamp": datetime.now(),
                "victim_ip": victim_ip,
                "action": "unblock",
                "details": f"Attack subsided after {attack_duration.total_seconds()/60:.2f} minutes, {blocked_sources} IPs were blocked"
            }
            self.mitigation_log.append(log_entry)
            
            # Add to attack history before removing from active attacks
            attack_history_entry = {
                "victim_ip": victim_ip,
                "start_time": attack_data['start_time'],
                "end_time": datetime.now(),
                "duration_seconds": attack_duration.total_seconds(),
                "blocked_sources": blocked_sources,
                "max_intensity": attack_data['attack_intensity']
            }
            self.attack_history.append(attack_history_entry)
            
            # Remove from active attacks
            del self.active_attacks[victim_ip]
            
            # Save updated mitigation log
            self.save_mitigation_log()
            
            # Generate post-mitigation report for this specific attack
            try:
                self.logger.info(f"Generating post-mitigation report for attack on {victim_ip}...")
                report_path = self.traffic_viz.generate_attack_specific_report(
                    victim_ip,
                    attack_history_entry,
                    f'post_mitigation_{victim_ip.replace(".", "_")}.png'
                )
                self.logger.info(f"Post-mitigation report generated: {report_path}")
            except Exception as viz_error:
                self.logger.error(f"Error generating post-mitigation report: {viz_error}")
                
            self.logger.info(f"Mitigation for attack on {victim_ip} ended successfully")
            
        except Exception as e:
            self.logger.error(f"Error in end_attack_mitigation: {e}")

    def delete_flow_by_victim(self, datapath, victim_ip):
        """Delete all flows protecting a specific victim IP."""
        try:
            self.logger.debug(f"Deleting protective flows for {victim_ip} from datapath {datapath.id}")
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Create a match for flows with the specific victim IP destination
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_dst=victim_ip
            )
            
            # Create flow deletion instruction
            instructions = []
            
            # Delete flow mod message
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=100,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
                instructions=instructions
            )
            
            datapath.send_msg(mod)
            self.logger.info(f"Deleted all protective flows for {victim_ip} from datapath {datapath.id}")
        except Exception as e:
            self.logger.error(f"Error deleting flows for {victim_ip}: {e}")

    def save_mitigation_log(self):
        """Save the mitigation log and attack history to CSV files."""
        try:
            self.logger.debug("Saving mitigation logs...")
            
            # Save mitigation actions log
            log_df = pd.DataFrame(self.mitigation_log)
            log_df.to_csv('mitigation_log.csv', index=False)
            
            # Save attack history
            if self.attack_history:
                history_df = pd.DataFrame(self.attack_history)
                history_df.to_csv('attack_history.csv', index=False)
            
            # Save current active attacks snapshot
            active_attacks_list = []
            for victim_ip, data in self.active_attacks.items():
                active_attacks_list.append({
                    'victim_ip': victim_ip,
                    'start_time': data['start_time'],
                    'current_duration': (datetime.now() - data['start_time']).total_seconds(),
                    'blocked_sources': len(data['blocked_ips']),
                    'last_activity': data['last_update'],
                    'current_intensity': data['attack_intensity']
                })
            
            if active_attacks_list:
                active_df = pd.DataFrame(active_attacks_list)
                active_df.to_csv('active_attacks.csv', index=False)
                
            self.logger.debug("All mitigation logs saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving mitigation logs: {e}")
