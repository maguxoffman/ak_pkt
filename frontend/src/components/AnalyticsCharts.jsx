import React from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine,
  BarChart, Bar, Cell, PieChart, Pie
} from 'recharts';

export default function AnalyticsCharts({ packets, stats }) {
  // Extract recent 30 scores for score timeline chart
  const scoreData = (packets || []).slice(-30).map((p, i) => ({
    time: p.time_str,
    score: p.score,
    threshold: p.threshold || stats?.threshold || 0.65,
    isAnomaly: p.is_anomaly_01
  }));

  // Top suspicious IPs
  const topIps = (stats?.top_suspicious_ips || []).map(([ip, count]) => ({
    ip,
    anomalies: count
  }));

  // Protocol ratio data
  const protoData = Object.entries(stats?.protocol_counts || {}).map(([name, count]) => ({
    name,
    value: count
  }));

  const PIE_COLORS = ['#06b6d4', '#f43f5e', '#f59e0b', '#10b981', '#8b5cf6'];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
      {/* Chart 1: Isolation Score Timeline & 99.9% Threshold */}
      <div className="glass-panel p-4 lg:col-span-2">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-white">Isolation Forest Anomaly Score Stream</h3>
            <p className="text-xs text-slate-400">Score vs. Dynamic 99.9% Percentile Threshold Line</p>
          </div>
          <span className="px-2 py-1 bg-rose-500/20 text-rose-300 font-mono text-xs border border-rose-500/30 rounded">
            Cutoff: {stats?.threshold || 0.65}
          </span>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={scoreData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="scoreGlow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
              <YAxis domain={[0, 1]} stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                itemStyle={{ color: '#f43f5e' }}
              />
              <ReferenceLine y={stats?.threshold || 0.65} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: 'Top 0.1% Threshold', fill: '#f59e0b', fontSize: 10 }} />
              <Area type="monotone" dataKey="score" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#scoreGlow)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 2: Top Suspicious IPs */}
      <div className="glass-panel p-4">
        <div className="mb-4">
          <h3 className="text-sm font-bold text-white">Top 0.1% Anomaly Sources</h3>
          <p className="text-xs text-slate-400">IPs Triggering 99.9 Percentile Anomaly Cutoff</p>
        </div>

        <div className="h-64 w-full">
          {topIps.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topIps} layout="vertical" margin={{ top: 5, right: 20, left: 30, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10 }} />
                <YAxis dataKey="ip" type="category" stroke="#94a3b8" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }} />
                <Bar dataKey="anomalies" fill="#f43f5e" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              No Threat IPs Flagged Yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
