import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta
import os
import numpy as np
import pickle
from collections import defaultdict
import seaborn as sns

class TrafficVisualization:
    """
    A class for collecting, analyzing, and visualizing network traffic data
    during normal operation, DDoS attacks, and after mitigation.
    """
    
    def __init__(self, log_path='./traffic_metrics.pkl', output_dir='./traffic_visualizations'):
        """
        Initialize the traffic visualization module.
        
        Args:
            log_path: Path to store the traffic metrics data
            output_dir: Directory to save visualization outputs
        """
        self.log_path = log_path
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Use a more modern style for plots
        plt.style.use('seaborn-v0_8-darkgrid')
        
        # Define a better color palette
        self.colors = {
            'legitimate': '#2ecc71',  # Green
            'malicious': '#e74c3c',   # Red
            'blocked': '#3498db',     # Blue
            'mitigation': '#9b59b6',  # Purple
            'background': '#f1c40f'   # Yellow
        }
            
        # Initialize or load traffic data
        if os.path.exists(log_path):
            with open(log_path, 'rb') as f:
                self.traffic_data = pickle.load(f)
        else:
            self.traffic_data = {
                'timestamps': [],
                'total_flows': [],
                'legitimate_flows': [],
                'ddos_flows': [],
                'mitigation_status': [],
                'blocked_sources': [],
                'packet_rates': defaultdict(list),
                'byte_rates': defaultdict(list),
                'victim_ips': [],
                # Add new fields for better attack tracking
                'attack_specific_metrics': defaultdict(list),
                'mitigation_effectiveness': []
            }
    
    def record_traffic_metrics(self, timestamp, legitimate_count, ddos_count, 
                              mitigation_active, blocked_sources_count, 
                              flow_stats_df=None, victim_ips=None):
        """
        Record traffic metrics for a given monitoring cycle.
        
        Args:
            timestamp: Current timestamp
            legitimate_count: Number of legitimate flows detected
            ddos_count: Number of DDoS flows detected
            mitigation_active: Boolean indicating if mitigation is active
            blocked_sources_count: Number of currently blocked sources
            flow_stats_df: DataFrame containing flow statistics
            victim_ips: List of victim IPs if identified
        """
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        self.traffic_data['timestamps'].append(timestamp)
        self.traffic_data['total_flows'].append(legitimate_count + ddos_count)
        self.traffic_data['legitimate_flows'].append(legitimate_count)
        self.traffic_data['ddos_flows'].append(ddos_count)
        self.traffic_data['mitigation_status'].append(1 if mitigation_active else 0)
        self.traffic_data['blocked_sources'].append(blocked_sources_count)
        
        # Store multiple victim IPs if available
        if victim_ips:
            if isinstance(victim_ips, list):
                self.traffic_data['victim_ips'].append(victim_ips)
            else:
                self.traffic_data['victim_ips'].append([victim_ips])
        else:
            self.traffic_data['victim_ips'].append([])
        
        # Process detailed flow statistics if available
        if flow_stats_df is not None:
            # Calculate average packet and byte rates
            avg_pps = flow_stats_df['packet_count_per_second'].mean()
            avg_bps = flow_stats_df['byte_count_per_second'].mean()
            
            self.traffic_data['packet_rates']['overall'].append(avg_pps)
            self.traffic_data['byte_rates']['overall'].append(avg_bps)
            
            # Calculate max packet and byte rates for threshold detection
            max_pps = flow_stats_df['packet_count_per_second'].max()
            max_bps = flow_stats_df['byte_count_per_second'].max()
            
            # Store mitigation effectiveness metrics
            if mitigation_active and ddos_count > 0:
                self.traffic_data['mitigation_effectiveness'].append(
                    blocked_sources_count / (legitimate_count + ddos_count) if (legitimate_count + ddos_count) > 0 else 0
                )
            else:
                self.traffic_data['mitigation_effectiveness'].append(0)
        
        # Save updated traffic data
        with open(self.log_path, 'wb') as f:
            pickle.dump(self.traffic_data, f)
    
    def generate_all_visualizations(self):
        """
        Generate all available traffic visualizations.
        
        Returns:
            Dict mapping visualization types to file paths
        """
        result = {}
        
        # Basic traffic flow visualization
        result['flow_trends'] = self.generate_flow_visualization()
        
        # Mitigation effectiveness
        if any(self.traffic_data['mitigation_status']):
            result['mitigation'] = self.generate_mitigation_visualization()
        
        # Attack pattern visualization
        if any(self.traffic_data['ddos_flows']):
            result['attack_patterns'] = self.generate_attack_pattern_visualization()
        
        return result
    
    def generate_flow_visualization(self):
        """
        Generate visualization of traffic flow trends over time with improved visuals.
        
        Returns:
            Path to the saved visualization file
        """
        if not self.traffic_data['timestamps']:
            return None
            
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Plot flow counts with better styling
        ax.plot(self.traffic_data['timestamps'], self.traffic_data['legitimate_flows'], 
               label='Legitimate Traffic', color=self.colors['legitimate'], linewidth=3)
        ax.plot(self.traffic_data['timestamps'], self.traffic_data['ddos_flows'], 
               label='Malicious Traffic', color=self.colors['malicious'], linewidth=3)
        
        # Add shaded areas for periods when mitigation was active
        mitigation_periods = []
        current_period = None
        
        for i, status in enumerate(self.traffic_data['mitigation_status']):
            if status and current_period is None:
                # Start of a mitigation period
                current_period = i
            elif not status and current_period is not None:
                # End of a mitigation period
                mitigation_periods.append((current_period, i-1))
                current_period = None
        
        # Handle case where mitigation is still active at the end
        if current_period is not None:
            mitigation_periods.append((current_period, len(self.traffic_data['mitigation_status'])-1))
        
        # Shade mitigation periods
        for start_idx, end_idx in mitigation_periods:
            ax.axvspan(
                self.traffic_data['timestamps'][start_idx],
                self.traffic_data['timestamps'][end_idx],
                alpha=0.2, color=self.colors['background'],
                label='Mitigation Active' if mitigation_periods.index((start_idx, end_idx)) == 0 else ""
            )
        
        # Add blocked sources as filled area
        ax.fill_between(
            self.traffic_data['timestamps'],
            self.traffic_data['blocked_sources'],
            alpha=0.4, color=self.colors['blocked'],
            label='Blocked Sources'
        )
        
        # Format the plot
        ax.set_title('Network Traffic Flow Analysis', fontsize=20, fontweight='bold')
        ax.set_xlabel('Time', fontsize=14, fontweight='bold')
        ax.set_ylabel('Count', fontsize=14, fontweight='bold')
        
        # Add grid but make it subtle
        ax.grid(True, linestyle='--', alpha=0.4)
        
        # Format tick labels
        ax.tick_params(axis='both', which='major', labelsize=12)
        
        # Format x-axis to show readable time
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        fig.autofmt_xdate()
        
        # Add annotations for significant events
        max_ddos = max(self.traffic_data['ddos_flows']) if self.traffic_data['ddos_flows'] else 0
        if max_ddos > 0:
            max_index = self.traffic_data['ddos_flows'].index(max_ddos)
            ax.annotate(f'Peak Attack: {max_ddos} flows', 
                      xy=(self.traffic_data['timestamps'][max_index], max_ddos),
                      xytext=(20, 20), textcoords='offset points',
                      arrowprops=dict(arrowstyle='->', lw=1.5, color='black', connectionstyle='arc3,rad=.2'),
                      fontsize=12, fontweight='bold', 
                      bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        # Add legend with better styling
        legend = ax.legend(loc='upper right', fontsize=12, frameon=True, 
                         facecolor='white', edgecolor='gray')
        legend.get_frame().set_alpha(0.9)
        
        # Add timestamp of generation
        plt.figtext(0.02, 0.02, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                   fontsize=8, fontstyle='italic')
        
        # Save the figure with higher resolution
        output_path = os.path.join(self.output_dir, 'flow_trends.png')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_mitigation_visualization(self):
        """
        Generate visualization showing the effectiveness of DDoS mitigation with improved visuals.
        
        Returns:
            Path to the saved visualization file
        """
        if not any(self.traffic_data['mitigation_status']):
            return None
            
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), gridspec_kw={'height_ratios': [2, 1]})
        
        # Plot 1: DDoS flows vs Blocked sources with area fills
        ax1.plot(self.traffic_data['timestamps'], self.traffic_data['ddos_flows'], 
               label='Malicious Flows', color=self.colors['malicious'], linewidth=3)
        ax1.fill_between(self.traffic_data['timestamps'], self.traffic_data['ddos_flows'], 
                        alpha=0.3, color=self.colors['malicious'])
        
        ax1.plot(self.traffic_data['timestamps'], self.traffic_data['blocked_sources'], 
               label='Blocked Sources', color=self.colors['blocked'], linewidth=3)
        ax1.fill_between(self.traffic_data['timestamps'], self.traffic_data['blocked_sources'], 
                        alpha=0.3, color=self.colors['blocked'])
        
        ax1.set_title('DDoS Attack & Mitigation Analysis', fontsize=18, fontweight='bold')
        ax1.set_ylabel('Count', fontsize=14, fontweight='bold')
        
        # Calculate and highlight correlation between attacks and blocked sources
        correlation = np.corrcoef(self.traffic_data['ddos_flows'], self.traffic_data['blocked_sources'])[0, 1]
        
        # Add correlation info
        ax1.text(0.02, 0.95, f"Correlation: {correlation:.2f}", 
                transform=ax1.transAxes, fontsize=12, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        # Add legend with better styling
        legend1 = ax1.legend(loc='upper right', fontsize=12, frameon=True,
                            facecolor='white', edgecolor='gray')
        legend1.get_frame().set_alpha(0.9)
        
        # Plot 2: Mitigation effectiveness score with gradient fill
        effectiveness = self.traffic_data['mitigation_effectiveness']
        ax2.plot(self.traffic_data['timestamps'], effectiveness, 
               color=self.colors['mitigation'], linewidth=3)
        
        # Create gradient fill based on effectiveness value
        for i in range(1, len(self.traffic_data['timestamps'])):
            ax2.fill_between(
                [self.traffic_data['timestamps'][i-1], self.traffic_data['timestamps'][i]],
                [effectiveness[i-1], effectiveness[i]],
                alpha=0.5,
                color=self.colors['mitigation']
            )
        
        ax2.set_title('Mitigation Effectiveness Score', fontsize=16, fontweight='bold')
        ax2.set_xlabel('Time', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Score (0-1)', fontsize=14, fontweight='bold')
        ax2.set_ylim(0, 1.0)
        
        # Add effectiveness thresholds
        ax2.axhline(y=0.75, color='green', linestyle='--', alpha=0.7, label='Excellent')
        ax2.axhline(y=0.5, color='orange', linestyle='--', alpha=0.7, label='Good')
        ax2.axhline(y=0.25, color='red', linestyle='--', alpha=0.7, label='Poor')
        
        # Add legend for thresholds
        legend2 = ax2.legend(loc='upper right', fontsize=12, frameon=True,
                            facecolor='white', edgecolor='gray')
        legend2.get_frame().set_alpha(0.9)
        
        # Format x-axis to show readable time for both subplots
        for ax in [ax1, ax2]:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            ax.xaxis.set_major_locator(mdates.AutoDateLocator())
            ax.tick_params(axis='both', which='major', labelsize=12)
            ax.grid(True, linestyle='--', alpha=0.4)
        
        # Add overall summary statistics
        avg_effectiveness = np.mean(effectiveness)
        max_effectiveness = np.max(effectiveness)
        
        summary_text = (
            f"Summary Statistics:\n"
            f"Avg. Effectiveness: {avg_effectiveness:.2f}\n"
            f"Max. Effectiveness: {max_effectiveness:.2f}\n"
            f"Total Blocked: {max(self.traffic_data['blocked_sources'])}"
        )
        
        ax2.text(0.02, 0.5, summary_text,
                transform=ax2.transAxes, fontsize=11,
                bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="gray", alpha=0.8))
        
        # Add timestamp of generation
        plt.figtext(0.02, 0.01, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                   fontsize=8, fontstyle='italic')
        
        # Save the figure with higher resolution
        output_path = os.path.join(self.output_dir, 'mitigation_effectiveness.png')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_attack_pattern_visualization(self):
        """
        Generate visualization showing attack patterns with improved visuals.
        
        Returns:
            Path to the saved visualization file
        """
        if not any(self.traffic_data['ddos_flows']):
            return None
            
        fig = plt.figure(figsize=(16, 12))
        
        # Create a more complex layout with GridSpec
        gs = plt.GridSpec(3, 3, figure=fig)
        ax1 = fig.add_subplot(gs[0, :])  # Attack intensity over time (top row)
        ax2 = fig.add_subplot(gs[1, :])  # Heatmap of victim IPs over time (middle row)
        ax3 = fig.add_subplot(gs[2, 0])  # Attack distribution pie chart (bottom left)
        ax4 = fig.add_subplot(gs[2, 1:])  # Attack timeline (bottom right)
        
        # Plot 1: Attack intensity over time with gradient fill
        ax1.plot(self.traffic_data['timestamps'], self.traffic_data['ddos_flows'], 
               color=self.colors['malicious'], linewidth=3)
        
        # Create gradient fill
        for i in range(1, len(self.traffic_data['timestamps'])):
            ax1.fill_between(
                [self.traffic_data['timestamps'][i-1], self.traffic_data['timestamps'][i]],
                [self.traffic_data['ddos_flows'][i-1], self.traffic_data['ddos_flows'][i]],
                alpha=0.5,
                color=self.colors['malicious']
            )
        
        ax1.set_title('DDoS Attack Intensity Over Time', fontsize=16, fontweight='bold')
        ax1.set_ylabel('Malicious Flows', fontsize=12, fontweight='bold')
        ax1.grid(True, linestyle='--', alpha=0.4)
        ax1.tick_params(axis='both', which='major', labelsize=10)
        
        # Format x-axis
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        ax1.xaxis.set_major_locator(mdates.AutoDateLocator())
        
        # Add peak attack annotation
        max_ddos = max(self.traffic_data['ddos_flows']) if self.traffic_data['ddos_flows'] else 0
        if max_ddos > 0:
            max_index = self.traffic_data['ddos_flows'].index(max_ddos)
            ax1.annotate(f'Peak: {max_ddos} flows', 
                       xy=(self.traffic_data['timestamps'][max_index], max_ddos),
                       xytext=(20, 20), textcoords='offset points',
                       arrowprops=dict(arrowstyle='->', lw=1.5, color='black', connectionstyle='arc3,rad=.2'),
                       fontsize=11, fontweight='bold', 
                       bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        # Plot 2: Enhanced heatmap of victim IPs over time
        unique_victims = set()
        for victims in self.traffic_data['victim_ips']:
            unique_victims.update(victims)
        
        unique_victims = list(unique_victims)
        if unique_victims:
            heatmap_data = np.zeros((len(unique_victims), len(self.traffic_data['timestamps'])))
            
            for t, victims in enumerate(self.traffic_data['victim_ips']):
                for victim in victims:
                    if victim in unique_victims:
                        v_idx = unique_victims.index(victim)
                        heatmap_data[v_idx, t] = 1
            
            # Plot enhanced heatmap with better colormap
            sns.heatmap(heatmap_data, cmap="YlOrRd", ax=ax2, cbar_kws={'label': 'Attack Activity'})
            ax2.set_title('Attack Targets Visualization', fontsize=16, fontweight='bold')
            ax2.set_xlabel('Time Point', fontsize=12, fontweight='bold')
            ax2.set_ylabel('Target IP', fontsize=12, fontweight='bold')
            ax2.set_yticks(np.arange(0.5, len(unique_victims), 1))
            ax2.set_yticklabels(unique_victims, rotation=0, fontsize=10)
            
            # Format x-axis to represent time points
            ax2.set_xticks(np.arange(0.5, len(self.traffic_data['timestamps']), 
                                    max(1, len(self.traffic_data['timestamps'])//10)))
            time_labels = [t.strftime('%H:%M:%S') for t in 
                          self.traffic_data['timestamps'][::max(1, len(self.traffic_data['timestamps'])//10)]]
            ax2.set_xticklabels(time_labels, rotation=45, fontsize=10)
        else:
            ax2.text(0.5, 0.5, "No victim IPs recorded", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, fontweight='bold')
        
        # Plot 3: Attack distribution pie chart
        if unique_victims:
            # Count attacks per victim
            victim_counts = {}
            for victims in self.traffic_data['victim_ips']:
                for victim in victims:
                    if victim in victim_counts:
                        victim_counts[victim] += 1
                    else:
                        victim_counts[victim] = 1
            
            labels = list(victim_counts.keys())
            sizes = list(victim_counts.values())
            
            # Create explode list to emphasize the most attacked victim
            explode = [0.1 if s == max(sizes) else 0 for s in sizes]
            
            wedges, texts, autotexts = ax3.pie(
                sizes, explode=explode, labels=None, autopct='%1.1f%%',
                shadow=True, startangle=90, colors=sns.color_palette('Set3', len(sizes))
            )
            
            # Customize text properties
            for autotext in autotexts:
                autotext.set_color('black')
                autotext.set_fontsize(9)
                autotext.set_fontweight('bold')
            
            ax3.set_title('Attack Distribution by Target', fontsize=14, fontweight='bold')
            
            # Add a custom legend for the pie chart
            ax3.legend(
                wedges, labels, title="Target IPs",
                loc="center left", bbox_to_anchor=(-0.1, 0, 0, 0),
                fontsize=8
            )
        else:
            ax3.text(0.5, 0.5, "No victim data available", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, fontweight='bold')
            ax3.axis('off')
        
        # Plot 4: Attack timeline visualization
        attack_periods = []
        current_period = None
        threshold = max(self.traffic_data['ddos_flows']) * 0.1 if self.traffic_data['ddos_flows'] else 0
        
        for i, flows in enumerate(self.traffic_data['ddos_flows']):
            if flows > threshold and current_period is None:
                # Start of an attack period
                current_period = i
            elif (flows <= threshold or i == len(self.traffic_data['ddos_flows'])-1) and current_period is not None:
                # End of an attack period
                attack_periods.append((current_period, i))
                current_period = None
        
        ax4.set_title('Attack Timeline Analysis', fontsize=14, fontweight='bold')
        ax4.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax4.set_yticks([])  # Hide y-axis ticks
        
        # Plot attack periods as horizontal bars
        if attack_periods:
            for i, (start, end) in enumerate(attack_periods):
                start_time = self.traffic_data['timestamps'][start]
                end_time = self.traffic_data['timestamps'][min(end, len(self.traffic_data['timestamps'])-1)]
                duration = (end_time - start_time).total_seconds()
                
                # Find victims for this period
                period_victims = set()
                for j in range(start, min(end+1, len(self.traffic_data['victim_ips']))):
                    period_victims.update(self.traffic_data['victim_ips'][j])
                
                victims_str = ", ".join(list(period_victims)[:3])
                if len(period_victims) > 3:
                    victims_str += f" +{len(period_victims) - 3} more"
                
                # Calculate attack intensity for this period
                intensity = max(self.traffic_data['ddos_flows'][start:end+1])
                
                # Plot horizontal bar
                ax4.barh(
                    i, duration, left=mdates.date2num(start_time),
                    color=self.colors['malicious'], alpha=0.7,
                    height=0.5
                )
                
                # Add text label
                ax4.text(
                    mdates.date2num(start_time) + duration/2, i,
                    f"Attack {i+1}: {duration:.1f}s, {victims_str}",
                    ha='center', va='center', fontsize=9, fontweight='bold',
                    color='white'
                )
            
            # Set y-axis limits
            ax4.set_ylim(-0.5, len(attack_periods) - 0.5)
            # Set custom y-tick labels
            ax4.set_yticks(range(len(attack_periods)))
            ax4.set_yticklabels([f"Attack {i+1}" for i in range(len(attack_periods))], fontsize=10)
            
            # Format x-axis to show readable time
            ax4.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            ax4.xaxis.set_major_locator(mdates.AutoDateLocator())
        else:
            ax4.text(0.5, 0.5, "No distinct attack periods detected", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, fontweight='bold')
            ax4.axis('off')
        
        # Add overall title
        plt.suptitle('Comprehensive DDoS Attack Pattern Analysis', fontsize=20, fontweight='bold', y=0.98)
        
        # Add timestamp of generation
        plt.figtext(0.02, 0.01, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                   fontsize=8, fontstyle='italic')
        
        # Save the figure with higher resolution
        output_path = os.path.join(self.output_dir, 'attack_patterns.png')
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_attack_specific_visualization(self, victim_ip, blocked_sources, start_time, filename):
        """
        Generate visualization specific to a single attack and its mitigation with improved visuals.
        
        Args:
            victim_ip: IP address of the victim
            blocked_sources: Number of blocked sources
            start_time: When the attack started
            filename: Output filename
        
        Returns:
            Path to the saved visualization file
        """
        plt.figure(figsize=(12, 8))
        
        # Get attack-specific metrics for this victim
        timestamps = []
        attack_intensities = []
        blocked_counts = []
        
        for i, t in enumerate(self.traffic_data['timestamps']):
            # Only include data points from after the attack started
            if t >= start_time:
                timestamps.append(t)
                
                # Find DDoS flows for this victim
                if victim_ip in self.traffic_data['victim_ips'][i]:
                    attack_intensities.append(self.traffic_data['ddos_flows'][i])
                else:
                    attack_intensities.append(0)
                
                blocked_counts.append(self.traffic_data['blocked_sources'][i])
        
        if not timestamps:
            return None
            
        # Plot attack intensity with improved styling
        plt.plot(timestamps, attack_intensities, label='Attack Intensity', 
                color=self.colors['malicious'], linewidth=3)
        plt.fill_between(timestamps, attack_intensities, alpha=0.3, color=self.colors['malicious'])
        
        # Plot blocked sources
        plt.plot(timestamps, blocked_counts, label='Blocked Sources', 
                color=self.colors['blocked'], linewidth=3)
        plt.fill_between(timestamps, blocked_counts, alpha=0.3, color=self.colors['blocked'])
        
        # Format the plot
        plt.title(f'DDoS Attack Mitigation for {victim_ip}', fontsize=18, fontweight='bold')
        plt.xlabel('Time', fontsize=14, fontweight='bold')
        plt.ylabel('Count', fontsize=14, fontweight='bold')
        plt.grid(True, linestyle='--', alpha=0.4)
        plt.tick_params(axis='both', which='major', labelsize=12)
        
        # Format x-axis to show readable time
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.gcf().autofmt_xdate()
        
        # Add legend with better styling
        legend = plt.legend(loc='upper right', fontsize=12, frameon=True,
                          facecolor='white', edgecolor='gray')
        legend.get_frame().set_alpha(0.9)
        
        # Add text annotation with attack details
        attack_duration = (timestamps[-1] - timestamps[0]).total_seconds() if timestamps else 0
        max_intensity = max(attack_intensities) if attack_intensities else 0
        
        info_text = (
            f"Attack on {victim_ip}\n"
            f"Started: {start_time.strftime('%H:%M:%S')}\n"
            f"Duration: {attack_duration:.1f} seconds\n"
            f"Peak Intensity: {max_intensity} flows\n"
            f"Blocked Sources: {blocked_sources}"
        )
        
        plt.annotate(
            info_text,
            xy=(0.02, 0.85), xycoords='axes fraction',
            fontsize=12, fontweight='bold',
            bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="gray", alpha=0.9)
        )
        
        # Add timestamp of generation
        plt.figtext(0.02, 0.01, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                   fontsize=8, fontstyle='italic')
        
        # Save the figure with higher resolution
        output_path = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_attack_specific_report(self, victim_ip, attack_data, filename):
        """
        Generate a comprehensive report for a specific attack after mitigation with improved visuals.
        
        Args:
            victim_ip: IP address of the victim
            attack_data: Dictionary containing attack details
            filename: Output filename
            
        Returns:
            Path to the saved report file
        """
        fig = plt.figure(figsize=(14, 12))
        
        # Create a more informative layout with GridSpec
        gs = plt.GridSpec(3, 2, figure=fig, height_ratios=[1, 1, 1.2])
        ax1 = fig.add_subplot(gs[0, 0])  # Attack timeline
        ax2 = fig.add_subplot(gs[0, 1])  # Mitigation effectiveness
        ax3 = fig.add_subplot(gs[1, :])  # Attack intensity heatmap
        ax4 = fig.add_subplot(gs[2, :])  # Summary statistics
        
        # Extract attack timeline
        start_time = attack_data['start_time']
        end_time = attack_data['end_time']
        duration_mins = attack_data['duration_seconds'] / 60
        
        # Filter data for this specific attack timeframe
        attack_timestamps = []
        attack_intensities = []
        blocked_counts = []
        
        for i, t in enumerate(self.traffic_data['timestamps']):
            if start_time <= t <= end_time:
                attack_timestamps.append(t)
                
                # Find DDoS flows for this victim
                if victim_ip in self.traffic_data['victim_ips'][i]:
                    attack_intensities.append(self.traffic_data['ddos_flows'][i])
                else:
                    attack_intensities.append(0)
                
                blocked_counts.append(self.traffic_data['blocked_sources'][i])
        
        # Plot 1: Attack timeline with gradient fill
        if attack_timestamps:
            ax1.plot(attack_timestamps, attack_intensities, color=self.colors['malicious'], linewidth=2.5)
            
            # Add gradient fill
            ax1.fill_between(attack_timestamps, attack_intensities, alpha=0.4, color=self.colors['malicious'])
            
            ax1.set_title('Attack Intensity Timeline', fontsize=14, fontweight='bold')
            ax1.set_ylabel('Malicious Flows', fontsize=12)
            ax1.grid(True, linestyle='--', alpha=0.4)
            ax1.tick_params(axis='both', which='major', labelsize=10)
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            
            # Add peak annotation
            if attack_intensities:
                max_intensity = max(attack_intensities)
                max_idx = attack_intensities.index(max_intensity)
                
                ax1.annotate(f'Peak: {max_intensity}',
                           xy=(attack_timestamps[max_idx], max_intensity),
                           xytext=(10, 15), textcoords='offset points',
                           arrowprops=dict(arrowstyle='->', lw=1.2, connectionstyle='arc3,rad=.2'),
                           fontsize=10, bbox=dict(boxstyle="round,pad=0.2", fc="white", alpha=0.8))
        else:
            ax1.text(0.5, 0.5, "No timeline data available", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=12)
            ax1.axis('off')
        
        # Plot 2: Mitigation effectiveness with visual indicators
        if attack_timestamps:
            ax2.plot(attack_timestamps, blocked_counts, color=self.colors['blocked'], linewidth=2.5)
            
            # Add gradient fill
            ax2.fill_between(attack_timestamps, blocked_counts, alpha=0.4, color=self.colors['blocked'])
            
            ax2.set_title('Mitigation Response', fontsize=14, fontweight='bold')
            ax2.set_ylabel('Blocked Sources', fontsize=12)
            ax2.grid(True, linestyle='--', alpha=0.4)
            ax2.tick_params(axis='both', which='major', labelsize=10)
            ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            
            # Calculate reaction time (time to first block after attack starts)
            if blocked_counts and any(blocked_counts):
                first_block_idx = next((i for i, count in enumerate(blocked_counts) if count > 0), None)
                if first_block_idx is not None:
                    reaction_time = (attack_timestamps[first_block_idx] - attack_timestamps[0]).total_seconds()
                    
                    ax2.annotate(f'Reaction time: {reaction_time:.1f}s',
                               xy=(attack_timestamps[first_block_idx], blocked_counts[first_block_idx]),
                               xytext=(10, -20), textcoords='offset points',
                               arrowprops=dict(arrowstyle='->', lw=1.2, connectionstyle='arc3,rad=.2'),
                               fontsize=10, bbox=dict(boxstyle="round,pad=0.2", fc="white", alpha=0.8))
        else:
            ax2.text(0.5, 0.5, "No mitigation data available", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=12)
            ax2.axis('off')
        
        # Plot 3: Attack intensity heatmap (time vs intensity visualization)
        if attack_timestamps:
            # Create time bins and intensity data
            time_range = mdates.date2num(attack_timestamps)
            intensity_bins = np.linspace(0, max(attack_intensities), 10) if attack_intensities else [0, 1]
            
            if len(time_range) > 1 and len(intensity_bins) > 1:
                # Create a 2D histogram
                hist_data, xedges, yedges = np.histogram2d(
                    time_range, 
                    attack_intensities, 
                    bins=[min(20, len(time_range)), min(10, len(intensity_bins))]
                )
                
                # Plot as a heatmap
                im = ax3.imshow(
                    hist_data.T, 
                    aspect='auto',
                    origin='lower',
                    extent=[xedges[0], xedges[-1], yedges[0], yedges[-1]],
                    cmap='inferno',
                    interpolation='nearest'
                )
                
                # Add colorbar
                cbar = plt.colorbar(im, ax=ax3)
                cbar.set_label('Frequency', fontsize=10)
                
                # Set labels
                ax3.set_title('Attack Intensity Distribution', fontsize=14, fontweight='bold')
                ax3.set_xlabel('Time', fontsize=12)
                ax3.set_ylabel('Attack Intensity (Flows)', fontsize=12)
                
                # Format x-axis for datetime
                time_formatter = mdates.AutoDateFormatter(mdates.AutoDateLocator())
                ax3.xaxis.set_major_formatter(time_formatter)
                ax3.tick_params(axis='both', which='major', labelsize=10)
            else:
                ax3.text(0.5, 0.5, "Insufficient data for heatmap visualization", 
                       horizontalalignment='center', verticalalignment='center',
                       fontsize=12)
                ax3.axis('off')
        else:
            ax3.text(0.5, 0.5, "No attack data available for heatmap", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=12)
            ax3.axis('off')
        
        # Plot 4: Enhanced summary statistics with visual indicators
        ax4.axis('off')
        
        # Create a styled report box
        report_width = 0.9
        report_height = 0.9
        report_rect = plt.Rectangle(
            (0.5-report_width/2, 0.5-report_height/2), 
            report_width, report_height, 
            transform=ax4.transAxes,
            facecolor='#f8f9fa', 
            edgecolor='gray',
            alpha=0.95,
            linewidth=2,
            zorder=1
        )
        ax4.add_patch(report_rect)
        
        # Create header section
        header_rect = plt.Rectangle(
            (0.5-report_width/2, 0.5+report_height/2-0.2), 
            report_width, 0.2, 
            transform=ax4.transAxes,
            facecolor=self.colors['malicious'], 
            edgecolor='none',
            alpha=0.8,
            zorder=2
        )
        ax4.add_patch(header_rect)
        
        # Add header text
        ax4.text(
            0.5, 0.5+report_height/2-0.1,
            "ATTACK MITIGATION REPORT",
            transform=ax4.transAxes,
            fontsize=16, fontweight='bold', color='white',
            horizontalalignment='center', verticalalignment='center',
            zorder=3
        )
        
        # Calculate advanced metrics
        if attack_intensities and blocked_counts:
            max_intensity = max(attack_intensities)
            avg_intensity = sum(attack_intensities) / len(attack_intensities) if attack_intensities else 0
            peak_blocked = max(blocked_counts) if blocked_counts else 0
            
            # Calculate effectiveness
            if max_intensity > 0:
                block_ratio = peak_blocked / max_intensity
            else:
                block_ratio = 0
                
            # Calculate mitigation speed (time to reach 50% of peak blocks after attack start)
            mitigation_speed = "N/A"
            if peak_blocked > 0:
                half_peak_idx = next((i for i, count in enumerate(blocked_counts) if count >= peak_blocked/2), None)
                if half_peak_idx is not None:
                    mitigation_speed = f"{(attack_timestamps[half_peak_idx] - attack_timestamps[0]).total_seconds():.1f}s"
        else:
            max_intensity = 0
            avg_intensity = 0
            peak_blocked = 0
            block_ratio = 0
            mitigation_speed = "N/A"
        
        # Format mitigation result message
        if block_ratio >= 0.8:
            result_msg = "ATTACK SUCCESSFULLY MITIGATED"
            result_color = "green"
        elif block_ratio >= 0.5:
            result_msg = "ATTACK PARTIALLY MITIGATED"
            result_color = "orange"
        else:
            result_msg = "ATTACK MITIGATION INCOMPLETE"
            result_color = "red"
        
        # Add summary text with better formatting
        summary_text = [
            ("Target IP:", victim_ip),
            ("Attack Start:", start_time.strftime('%Y-%m-%d %H:%M:%S')),
            ("Attack End:", end_time.strftime('%Y-%m-%d %H:%M:%S')),
            ("Duration:", f"{duration_mins:.2f} minutes"),
            ("Peak Intensity:", f"{attack_data['max_intensity']} malicious flows"),
            ("Avg. Intensity:", f"{avg_intensity:.1f} flows"),
            ("Total Blocked Sources:", f"{attack_data['blocked_sources']}"),
            ("Mitigation Speed:", mitigation_speed),
            ("Block Effectiveness:", f"{block_ratio:.1%}")
        ]
        
        # Position for starting text blocks
        start_y = 0.5 + report_height/2 - 0.3
        start_x = 0.5 - report_width/2 + 0.05
        
        # Add text items
        for i, (label, value) in enumerate(summary_text):
            # Label (left column)
            ax4.text(
                start_x, start_y - i*0.08, 
                label,
                transform=ax4.transAxes,
                fontsize=12, fontweight='bold',
                horizontalalignment='left', verticalalignment='center',
                zorder=3
            )
            
            # Value (right column)
            ax4.text(
                start_x + 0.4, start_y - i*0.08, 
                value,
                transform=ax4.transAxes,
                fontsize=12,
                horizontalalignment='left', verticalalignment='center',
                zorder=3
            )
        
        # Add horizontal divider line
        divider_y = start_y - len(summary_text)*0.08 - 0.05
        ax4.plot(
            [0.5-report_width/2+0.05, 0.5+report_width/2-0.05], 
            [divider_y, divider_y],
            transform=ax4.transAxes,
            color='gray', linestyle='-', linewidth=1,
            zorder=3
        )
        
        # Add result message
        ax4.text(
            0.5, divider_y - 0.08, 
            result_msg,
            transform=ax4.transAxes,
            fontsize=14, fontweight='bold', color=result_color,
            horizontalalignment='center', verticalalignment='center',
            zorder=3
        )
        
        # Add timestamp of generation
        ax4.text(
            0.5, 0.5-report_height/2+0.05, 
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            transform=ax4.transAxes,
            fontsize=8, fontstyle='italic', color='gray',
            horizontalalignment='center', verticalalignment='center',
            zorder=3
        )
        
        # Add overall title
        plt.suptitle(f"DDoS Attack Post-Mitigation Analysis for {victim_ip}", fontsize=18, fontweight='bold', y=0.98)
        
        # Save the figure with higher resolution
        output_path = os.path.join(self.output_dir, filename)
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def export_data_to_csv(self):
        """
        Export traffic metrics data to CSV for external analysis.
        
        Returns:
            Path to the exported CSV file
        """
        # Create a DataFrame from the traffic data
        df = pd.DataFrame({
            'timestamp': self.traffic_data['timestamps'],
            'total_flows': self.traffic_data['total_flows'],
            'legitimate_flows': self.traffic_data['legitimate_flows'],
            'ddos_flows': self.traffic_data['ddos_flows'],
            'mitigation_active': self.traffic_data['mitigation_status'],
            'blocked_sources': self.traffic_data['blocked_sources'],
            'mitigation_effectiveness': self.traffic_data['mitigation_effectiveness']
        })
        
        # Add packet rate data
        if 'overall' in self.traffic_data['packet_rates']:
            df['packet_rate_overall'] = self.traffic_data['packet_rates']['overall']
        
        if 'overall' in self.traffic_data['byte_rates']:
            df['byte_rate_overall'] = self.traffic_data['byte_rates']['overall']
        
        # Create a column for victim IPs (as comma-separated string)
        df['victim_ips'] = [','.join(victims) for victims in self.traffic_data['victim_ips']]
        
        # Save to CSV
        output_path = os.path.join(self.output_dir, 'traffic_metrics.csv')
        df.to_csv(output_path, index=False)
        
        return output_path
    
    def generate_dashboard(self, output_filename='dashboard.html'):
        """
        Generate an interactive HTML dashboard with all visualizations.
        
        Args:
            output_filename: Name of the HTML file to create
            
        Returns:
            Path to the saved HTML dashboard
        """
        # First generate all visualizations
        visualizations = self.generate_all_visualizations()
        
        # Create relative paths for the visualizations
        rel_paths = {}
        for viz_type, path in visualizations.items():
            if path:
                rel_paths[viz_type] = os.path.basename(path)
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DDoS Traffic Analysis Dashboard</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f8f9fa;
                    color: #212529;
                }}
                .header {{
                    background-color: #343a40;
                    color: white;
                    padding: 1rem;
                    text-align: center;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 1rem;
                }}
                .dashboard-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 1.5rem;
                    margin-top: 1rem;
                }}
                .full-width {{
                    grid-column: 1 / -1;
                }}
                .card {{
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    overflow: hidden;
                    transition: transform 0.3s ease;
                }}
                .card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }}
                .card-header {{
                    background-color: #495057;
                    color: white;
                    padding: 0.75rem 1rem;
                    font-weight: bold;
                }}
                .card-body {{
                    padding: 1rem;
                    text-align: center;
                }}
                .card-body img {{
                    max-width: 100%;
                    height: auto;
                    border-radius: 4px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 2rem;
                    padding: 1rem;
                    background-color: #343a40;
                    color: white;
                }}
                .summary {{
                    background-color: #e9ecef;
                    padding: 1rem;
                    border-radius: 8px;
                    margin-bottom: 1.5rem;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 1rem;
                }}
                .stat-card {{
                    background: white;
                    padding: 1rem;
                    border-radius: 8px;
                    text-align: center;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.05);
                }}
                .stat-value {{
                    font-size: 1.5rem;
                    font-weight: bold;
                    margin: 0.5rem 0;
                }}
                .stat-label {{
                    color: #6c757d;
                    font-size: 0.9rem;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>DDoS Traffic Analysis Dashboard</h1>
                <p>Visualization of network traffic during normal operation, DDoS attacks, and after mitigation</p>
            </div>
            
            <div class="container">
                <!-- Summary Statistics -->
                <div class="summary">
                    <h2>Summary Statistics</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-label">Total Traffic Flows</div>
                            <div class="stat-value">{sum(self.traffic_data['total_flows'])}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">Legitimate Flows</div>
                            <div class="stat-value">{sum(self.traffic_data['legitimate_flows'])}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">Malicious Flows</div>
                            <div class="stat-value">{sum(self.traffic_data['ddos_flows'])}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">Peak Attack Intensity</div>
                            <div class="stat-value">{max(self.traffic_data['ddos_flows']) if self.traffic_data['ddos_flows'] else 0}</div>
                        </div>
                    </div>
                </div>
                
                <!-- Visualizations -->
                <div class="dashboard-grid">
        """
        
        # Add cards for each visualization
        if 'flow_trends' in rel_paths:
            html_content += f"""
                    <div class="card full-width">
                        <div class="card-header">Network Traffic Flow Trends</div>
                        <div class="card-body">
                            <img src="{rel_paths['flow_trends']}" alt="Flow Trends Visualization">
                        </div>
                    </div>
            """
        
        if 'mitigation' in rel_paths:
            html_content += f"""
                    <div class="card full-width">
                        <div class="card-header">DDoS Mitigation Effectiveness</div>
                        <div class="card-body">
                            <img src="{rel_paths['mitigation']}" alt="Mitigation Effectiveness Visualization">
                        </div>
                    </div>
            """
        
        if 'attack_patterns' in rel_paths:
            html_content += f"""
                    <div class="card full-width">
                        <div class="card-header">Attack Pattern Analysis</div>
                        <div class="card-body">
                            <img src="{rel_paths['attack_patterns']}" alt="Attack Pattern Visualization">
                        </div>
                    </div>
            """
        
        # Close HTML tags
        html_content += """
                </div>
            </div>
            
            <div class="footer">
                <p>Generated by TrafficVisualization Tool - © 2025</p>
            </div>
        </body>
        </html>
        """
        
        # Save HTML file
        output_path = os.path.join(self.output_dir, output_filename)
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path
