import React from 'react';
import { Activity, AlertTriangle, Cpu, Layers } from 'lucide-react';

export default function MetricsOverview({ stats }) {
  const {
    total_packets = 0,
    anomalies_01_count = 0,
    max_score = 0,
    threshold = 0.65,
    protocol_counts = {}
  } = stats || {};

  const anomalyPercentage = total_packets > 0 
    ? ((anomalies_01_count / total_packets) * 100).toFixed(2) 
    : '0.00';

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Total Packets Card */}
      <div className="glass-panel p-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Packets Inspected</p>
          <h3 className="text-2xl font-extrabold text-white mt-1 font-mono">{total_packets.toLocaleString()}</h3>
          <p className="text-xs text-slate-500 mt-1">Real-time Stream Inspection</p>
        </div>
        <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded-xl">
          <Activity className="w-6 h-6" />
        </div>
      </div>

      {/* 0.1% Anomaly Detected Card */}
      <div className="glass-panel-anomaly p-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-1">
            Top 0.1% Anomalies
          </p>
          <h3 className="text-2xl font-extrabold text-rose-400 mt-1 font-mono flex items-baseline gap-2">
            {anomalies_01_count.toLocaleString()}
            <span className="text-xs font-normal text-rose-300">({anomalyPercentage}%)</span>
          </h3>
          <p className="text-xs text-rose-300/70 mt-1">99.9 Percentile Score Outliers</p>
        </div>
        <div className="p-3 bg-rose-500/20 border border-rose-500/40 text-rose-400 rounded-xl glow-anomaly">
          <AlertTriangle className="w-6 h-6" />
        </div>
      </div>

      {/* Max Anomaly Score & Threshold Card */}
      <div className="glass-panel p-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Max Isolation Score</p>
          <h3 className="text-2xl font-extrabold text-amber-400 mt-1 font-mono">{max_score}</h3>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-1 font-mono">
            Cutoff Threshold: <span className="text-cyan-400 font-bold">{threshold}</span>
          </p>
        </div>
        <div className="p-3 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-xl">
          <Cpu className="w-6 h-6" />
        </div>
      </div>

      {/* Protocol Distribution Summary Card */}
      <div className="glass-panel p-4 flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Traffic Protocols</p>
          <div className="flex gap-2 mt-2 flex-wrap font-mono text-xs">
            <span className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300">
              TCP: {protocol_counts.TCP || 0}
            </span>
            <span className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300">
              UDP: {protocol_counts.UDP || 0}
            </span>
            <span className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300">
              DNS: {protocol_counts.DNS || 0}
            </span>
          </div>
        </div>
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-xl">
          <Layers className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}
